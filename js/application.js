var faye = new Faye.Client('https://faye.chatchan.us/faye');

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

  $scope.privateKey = cryptico.generateRSAKey(generatePassword(40, false), 1024);
  $scope.me = {
    username: 'Anonymous',
    publicKey: cryptico.publicKeyString($scope.privateKey)
  }

  $scope.users = [];
  $scope.messages = [];
  $scope.newMessage = { content: '' }

  // Add a user, overwrite if it duplicates on public key
  $scope.addUser = function(newUser) {
    setTimeout(function() {
      newUser.publicKeyID = cryptico.publicKeyID(newUser.publicKey);
      newUser.color = '#' + newUser.publicKeyID.substring(0, 6);
      $scope.users = $scope.users.filter(function(user) {
        return user.publicKey != newUser.publicKey;
      });
      $scope.users.push(newUser);
      $scope.$apply();
    });
  }

  $scope.init = function() {
    $scope.me.publicKeyID = cryptico.publicKeyID($scope.me.publicKey);

    // Add users who acknowledged my arrival
    faye.subscribe('/users/' + $scope.me.publicKeyID + '/knockback', function(newUser) {
      $scope.addUser(newUser);
    });
  }
  $scope.init();

  $scope.knock = function() {
    if ($scope.me.username == '') return;

    // Initialize users list with me as first user
    $scope.users = [];
    $scope.addUser($scope.me);

    // Notify my arrival to users
    faye.publish('/users', $scope.me);

    // Be notified when other people arrive
    faye.subscribe('/users', function(newUser) {
      $scope.addUser(newUser);

      // And acknowledge that you received their notification
      faye.publish('/users/' + newUser.publicKeyID + '/knockback', $scope.me);
    });

    // Finaly, be ready to receive messages
    faye.subscribe('/users/' + $scope.me.publicKeyID + '/messages', function(message) {
      decrypt = cryptico.decrypt(message.content, $scope.privateKey);
      message.content = $sce.trustAsHtml(emoji.replace_unified(emoji.replace_emoticons(sanitize(decrypt.plaintext))));
      if (decrypt.signature == 'verified') {
        message.user = $scope.users.find(function(user) {
          return user.publicKey == decrypt.publicKeyString;
        });
        if (message.user !== undefined) {
          message.received_at = Date.now();
          $scope.messages.push(message);
          $scope.$apply();
          $scope.$autoScroll.scrollTop = $scope.$autoScroll.scrollHeight;
        } else {
          console.log("Info: can't find user for message", decrypt);
        }
      } else {
        console.log("Warning: forged signature for message", decrypt);
      }
    });

    // * randomly check if users are still connected
    // * all messages should be broadcasted to /users to hide their nature
    // * all message should be fully crypted, not only some values like content

    $scope.ready = true;
  };

  $scope.sendMessage = function(message) {
    if (message == '') return;
    $scope.users.forEach(function(user) {
      crypted_message = cryptico.encrypt(message, user.publicKey, $scope.privateKey).cipher;
      faye.publish('/users/' + user.publicKeyID + '/messages', { content: crypted_message });
    });
  };

  $scope.submitMessage = function() {
    $scope.newMessage.disabled = true;
    $scope.sendMessage($scope.newMessage.content);
    $scope.newMessage.content = '';
    $scope.newMessage.disabled = false;
  };
});
