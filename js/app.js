var debug = false;

if (debug) {
  var faye = {
    publish: function(channel, data) {
      setTimeout(function(){ faye.callbacks[channel](data) }, 50);
    },
    subscribe: function(channel, callback) {
      faye.callbacks[channel] = callback;
    },
    callbacks: {}
  }
} else {
  var faye = new Faye.Client('https://faye.chatchan.us/faye');
}

var markdown = window.markdownit().disable(['image', 'heading', 'lheading', 'hr']);

var emoji = new EmojiConvertor();
emoji.include_title = true;
emoji.img_sets.apple.sheet = 'apple.png';
emoji.use_sheet = true;

function sanitize(string){
  return string.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

var messagesApp = angular.module('messagesApp', []);

messagesApp.controller('messagesController', function($scope, $sce) {
  $scope.ready = false;
  $scope.$autoScroll = document.getElementById("auto-scroll");
  $scope.$messageContent = document.getElementById("messageContent");

  $scope.chan = {
    privateKey: cryptico.generateRSAKey(window.location.href, 1024)
  }
  $scope.chan.publicKey = cryptico.publicKeyString($scope.chan.privateKey);

  $scope.users = [];
  $scope.privateKey = cryptico.generateRSAKey(generatePassword(40, false), 1024);
  $scope.me = {
    username: '',
    publicKey: cryptico.publicKeyString($scope.privateKey)
  }

  $scope.messages = [];
  $scope.newMessage = { content: '' }

  // Add a user, overwrite if it duplicates on public key
  $scope.addUser = function(newUser) {
    setTimeout(function() {
      if (newUser.username == '') return false;

      newUser.received_at = Date.now();
      newUser.publicKeyID = cryptico.publicKeyID(newUser.publicKey);
      newUser.color = '#' + newUser.publicKeyID.substring(0, 6);
      $scope.users = $scope.users.filter(function(user) {
        return newUser.publicKey != user.publicKey;
      });
      $scope.users.push(newUser);
      $scope.users = $scope.users.sort(function(user1, user2) {
        return (user1.username + user1.publicKeyID).localeCompare(user2.username + user2.publicKeyID);
      });
      $scope.$apply();
    });
  }

  // Remove timed out users from your userlist
  $scope.cleanUsers = function() {
    $scope.users = $scope.users.filter(function(user) {
      return user.received_at > Date.now() - 60000;
    });
    setTimeout($scope.cleanUsers, 30000);
  }

  // Regularly ping users to spot timed out ones
  $scope.refreshUsers = function() {
    $scope.users.forEach(function(user) {
      faye.publish('/ciphers', $scope.cipherFromObject({
        data: {
          type: 'users',
          attributes: $scope.me,
        },
        meta: {
          synack: true
        }
      }, user.publicKey));
    });
    setTimeout($scope.refreshUsers, Math.random() * 30000);
  }

  // Send your publicKey to people
  $scope.knock = function() {
    if ($scope.me.username == '') {
      $scope.me.username = 'Anonymous';
    }

    faye.publish('/keys', $scope.me.publicKey);
    $scope.ready = true;
    setTimeout(function() { $scope.$messageContent.focus() });
    setTimeout($scope.refreshUsers, Math.random() * 30000);
    setTimeout($scope.cleanUsers, 30000);
  };

  // New people give their publickKey through /keys
  faye.subscribe('/keys', function(publicKey) {
    if (!$scope.ready) return false;

    // Then send them yours with your crypted username...
    faye.publish('/ciphers', $scope.cipherFromObject({
      data: {
        type: 'users',
        attributes: $scope.me,
      },

      // ... and ask for their crypted username.
      meta: {
        synack: true
      }
    }, publicKey));
  });

  // Be prepared to receive all crypted data through /ciphers
  faye.subscribe('/ciphers', function(cipher) { $scope.evalCipher(cipher); });

  // Everything (except your publicKey at first connection) will be sent crypted
  // With user privateKey and then chan privateKey
  $scope.cipherFromObject = function(object, publicKey) {
    return cryptico.encrypt(
      cryptico.encrypt(
        JSON.stringify(object), publicKey, $scope.privateKey
      ).cipher, $scope.chan.publicKey
    ).cipher;
  }

  // Reverses encryption with channel privateKey and yours,
  // then marks the object metadata with sender publicKey
  $scope.objectFromCipher = function(cipher) {
    decrypted = cryptico.decrypt(
      cipher, $scope.chan.privateKey
    );

    if (decrypted.status == 'success') {
      decrypted = cryptico.decrypt(
        decrypted.plaintext, $scope.privateKey
      );
    }

    if (decrypted.status == 'success') {
      if (decrypted.signature == 'verified') {
        object = JSON.parse(decrypted.plaintext);
        object.meta = object.meta || {};
        object.meta.publicKeyString = decrypted.publicKeyString;
        return object;
      } else {
        console.warn("Forged signature", decrypted);
      }
    }
    return false;
  }

  // All messages from /ciphers are evaluated here
  $scope.evalCipher = function(cipher) {
    object = $scope.objectFromCipher(cipher);

    // A lot of data will fail to be decrypted
    // since everything is always sent to everyone
    // in order to protect the recipient
    if (!object) return false;

    switch (object.data.type) {
      // Somebody sent you their username. Add them to your userlist
      case 'users':
        $scope.addUser({
          username: object.data.attributes.username,
          publicKey: object.meta.publicKeyString
        });

        // Send them back your username if they asked for iit
        if (object.meta.synack) {
          faye.publish('/ciphers', $scope.cipherFromObject({
            data: {
              type: 'users',
              attributes: $scope.me
            }
          }, object.meta.publicKeyString));
        }
        break;

      // Somebody sent you a message
      case 'messages':
        user = $scope.users.find(function(user) {
          return user.publicKey == object.meta.publicKeyString;
        })
        user.received_at = Date.now();
        $scope.addMessage({
          content: $scope.renderContent(object.data.attributes.content),
          user: user
        });
        $scope.renderCode();
        break;
      default:
        console.log('Unknown data type', object);
    }
  }

  $scope.renderCode = function() {
    setTimeout(function() {
      [].slice.call(document.getElementsByTagName("code")).forEach(function(element) {
        hljs.highlightBlock(element);
      });
    });
  }

  $scope.addMessage = function(message) {
    if (!message.user || !message.content) return false;

    setTimeout(function() {
      message.received_at = Date.now();
      $scope.messages.push(message);
      $scope.$apply();
      $scope.scrollDown();
    });
  }

  $scope.sendMessage = function(message) {
    if (message == '') return;

    $scope.users.forEach(function(user) {
      faye.publish('/ciphers',  $scope.cipherFromObject({
        data: {
          type: 'messages',
          attributes: {
            content: message.content
          }
        }
      }, user.publicKey));
    });
  };

  $scope.newMessage.interceptEnter = function(e) {
    if (e.keyCode == 13 && !e.shiftKey) {
      e.preventDefault();
      $scope.newMessage.disabled = true;
      $scope.sendMessage($scope.newMessage);
      $scope.newMessage.content = '';
      $scope.newMessage.disabled = false;
    }
  }

  $scope.scrollDown = function() {
    $scope.$autoScroll.scrollTop = $scope.$autoScroll.scrollHeight;
  }

  $scope.renderContent = function(content) {
    return $sce.trustAsHtml(
      emoji.replace_unified(
        emoji.replace_emoticons(
          markdown.render(
            content
          )
        )
      )
    );
  }
});
