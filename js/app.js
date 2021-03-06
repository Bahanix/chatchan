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

var markdown = window.markdownit({ linkify: true }).disable(['image', 'heading', 'lheading', 'hr']);

var emoji = new EmojiConvertor();
emoji.include_title = true;
emoji.img_sets.apple.sheet = 'images/apple.png';
emoji.use_sheet = true;

function sanitize(string){
  return string.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

var messagesApp = angular.module('messagesApp', []);

messagesApp.controller('messagesController', function($scope, $sce) {
  window.scope = $scope;
  $scope.$autoScroll = document.getElementById("auto-scroll");
  $scope.$messageContent = document.getElementById("messageContent");

  $scope.chans = [];
  $scope.currentChan = null;

  $scope.users = [];
  $scope.privateKey = cryptico.generateRSAKey(generatePassword(40, false), 1024);
  $scope.me = {
    username: '',
    publicKey: cryptico.publicKeyString($scope.privateKey)
  }
  $scope.me.publicKeyID = cryptico.publicKeyID($scope.me.publicKey);

  $scope.newMessage = { content: '' }
  $scope.unread = 0;
  $scope.originalTitle = document.title;

  $scope.addChan = function(name) {
    if ($scope.chans.find(function(chan) {
      return chan.name == name;
    })) {
      return false;
    }

    chan = {
      name: name,
      privateKey: cryptico.generateRSAKey(name, 1024),
      ready: false,
      messages: []
    }
    chan.publicKey = cryptico.publicKeyString(chan.privateKey);
    $scope.chans.push(chan);

    if ($scope.chans.length == 1) {
      $scope.setCurrentChan(chan);
    }

    return chan;
  }
  $scope.setCurrentChan = function(chan) {
    $scope.currentChan = chan;
    setTimeout(function() { $scope.scrollDown(); });
  }

  $scope.parseHash = function() {
    chans = location.hash.substr(location.hash.indexOf('#') + 1).split(",");
    oldChans = $scope.chans.map(function(chan) {return chan.name});
    newChans = chans.filter(function(i) {return oldChans.indexOf(i) < 0;});
    newChans.map($scope.addChan).forEach($scope.knock);
    $scope.chans = $scope.chans.filter(function(i) {return chans.indexOf(i.name) >= 0;}).sort(function(chan1, chan2) {
      return chan1.name.localeCompare(chan2.name);
    });
    setTimeout(function() { $scope.$apply() });
  }

  $scope.login = function() {
    $scope.parseHash();
    window.addEventListener('hashchange', $scope.parseHash);
  }

  if (!location.hash) location.hash = "#general,random,meta"

  window.addEventListener('focus', function() {
    $scope.unread = 0;
    $scope.setTitle();
  });

  $scope.setTitle = function() {
    if ($scope.unread >= 1) {
      document.title = '(' + $scope.unread + ') ' + $scope.originalTitle;
    } else {
      document.title = $scope.originalTitle;
    }
  }

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
    $scope.users.filter(function(user) {
      return user.received_at <= Date.now() - 60000;
    }).forEach(function(user) {
      $scope.addMessage({
        content: $scope.renderContent("*connection reset by peer*"),
        user: user
      });
    });

    $scope.users = $scope.users.filter(function(user) {
      return user.received_at > Date.now() - 60000;
    });
    setTimeout($scope.cleanUsers, 30000);
  }

  // Regularly ping users to spot timed out ones
  $scope.refreshUsers = function() {
    $scope.users.forEach(function(user) {
      setTimeout(function() {
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
    }, 20);
    setTimeout($scope.refreshUsers, Math.random() * 30000);
  }

  // Send your publicKey to your chan
  $scope.knock = function(chan) {
    if ($scope.me.username == '') {
      $scope.me.username = 'Anonymous';
    }

    faye.publish('/keys', cryptico.encrypt(
      $scope.me.publicKey, chan.publicKey
    ).cipher);

    chan.ready = true;
    setTimeout(function() { $scope.$messageContent.focus() });
    setTimeout($scope.refreshUsers, Math.random() * 30000);
    setTimeout($scope.cleanUsers, 30000);
  };

  // New people give their publickKey through /keys
  faye.subscribe('/keys', function(cryptedPublicKey) {
    senderChan = null;
    publicKey = null;

    $scope.chans.some(function(chan) {
      decrypted = cryptico.decrypt(
        cryptedPublicKey, chan.privateKey
      );

      if (decrypted.status == 'success') {
        senderChan = chan;
        publicKey = decrypted.plaintext;
        return true;
      } else {
        return false;
      }
    });


    if (!publicKey) {
      return false;
    }

    if (!senderChan.ready) return false;

    // Then send them yours with your crypted username...
    payload = {
      data: {
        type: 'users',
        attributes: $scope.me,
      },
      meta: {
        chan: senderChan.name
      }
    }

    // ... and ask for their crypted username.
    if (publicKey != $scope.me.publicKey) {
      payload.meta.synack = true;
    }

    faye.publish('/ciphers', $scope.cipherFromObject(payload, publicKey));
  });

  // Be prepared to receive all crypted data through /ciphers
  faye.subscribe('/ciphers', function(cipher) { $scope.evalCipher(cipher); });

  // Everything (except your publicKey at first connection) will be sent crypted
  $scope.cipherFromObject = function(object, publicKey) {
    return cryptico.encrypt(
      JSON.stringify(object), publicKey, $scope.privateKey
    ).cipher;
  }

  // Reverses encryption,
  // then marks the object metadata with sender publicKey
  $scope.objectFromCipher = function(cipher) {
    decrypted = cryptico.decrypt(
      cipher, $scope.privateKey
    );

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
        newUser = {
          username: object.data.attributes.username,
          publicKey: object.meta.publicKeyString
        }

        // object.meta.synack is true when people already here,
        // and we only want to display newcomers.
        if (!object.meta.synack && $scope.users.every(function(user) {
          return newUser.publicKey != user.publicKey;
        })) {
          $scope.addMessage(object.meta.chan, {
            content: $scope.renderContent("*joined the channel*"),
            user: newUser
          });
        }

        $scope.addUser(newUser);

        // Send them back your username if they asked for iit
        if (object.meta.synack) {
          faye.publish('/ciphers', $scope.cipherFromObject({
            data: {
              type: 'users',
              attributes: $scope.me
            },
            meta: {
              chan: object.meta.chan
            }
          }, object.meta.publicKeyString));
        }
        break;

      // Somebody sent you a message
      case 'messages':
        user = $scope.users.find(function(user) {
          return user.publicKey == object.meta.publicKeyString;
        })
        recipient = null;
        if (object.meta.recipient) {
          recipient = $scope.users.find(function(user) {
            return user.publicKeyID == object.meta.recipient;
          })
        }
        user.received_at = Date.now();
        $scope.addMessage(object.meta.chan, {
          content: $scope.renderContent(object.data.attributes.content),
          user: user,
          recipient: recipient
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

  $scope.addMessage = function(chanName, message) {
    if (!message || !message.user || !message.content) return false;

    chan = $scope.chans.find(function(chan) {
      return chan.name == chanName;
    });
    if (!chan) return false;

    if (!document.hasFocus()) {
      $scope.unread++;
      $scope.setTitle();
    }

    message.received_at = Date.now();
    chan.messages.push(message);
    $scope.$apply();
    $scope.scrollDown();
  }

  $scope.whisp = function(user) {
    if ($scope.newMessage.content.startsWith("/msg ")) {
      $scope.newMessage.content = $scope.newMessage.content.split(" ").splice(2).join(" ");
    }
    $scope.newMessage.content = "/msg " + user.publicKeyID + " " + $scope.newMessage.content;
    $scope.$messageContent.focus();
  }

  $scope.sendMessage = function(message) {
    if (message.content == '') return;

    recipient = null;
    if (message.content.startsWith("/msg ")) {
      recipient = message.content.split(" ")[1]
      users = $scope.users.filter(function(user) {
        return [recipient, $scope.me.publicKeyID].includes(user.publicKeyID);
      });
      message.content = message.content.split(" ").splice(2).join(" ");
    } else {
      users = $scope.users;
    }

    if (message.content.startsWith("/me ")) {
      message.content = "*" + message.content.split(" ").splice(1).join(" ") + "*";
    }

    payload = {
      data: {
        type: 'messages',
        attributes: {
          content: message.content
        }
      },
      meta: {
        chan: $scope.currentChan.name
      }
    }

    if (recipient) {
      payload.meta.recipient = recipient;
    }

    users.forEach(function(user) {
      setTimeout(function() {
        faye.publish('/ciphers',  $scope.cipherFromObject(payload, user.publicKey));
      }, 20);
    });
  };

  $scope.newMessage.resize = function(e) {
    $scope.$messageContent.style.height = Math.min(10, Math.max(2, $scope.$messageContent.value.match(/^/mg).length)) + 1 + "em";
    $scope.$autoScroll.scrollTop = $scope.$autoScroll.scrollHeight;
  }

  $scope.newMessage.interceptEnter = function(e) {
    if (e.keyCode == 13 && !e.shiftKey) {
      e.preventDefault();
      $scope.newMessage.disabled = true;
      $scope.sendMessage($scope.newMessage);
      $scope.newMessage.content = '';
      $scope.newMessage.disabled = false;
      $scope.$messageContent.style.height = "3em";
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
