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
  $scope.$autoScroll = document.getElementById("auto-scroll");

  $scope.ready = false;
  $scope.privateKey = cryptico.generateRSAKey(generatePassword(40, false), 1024);
  $scope.me = {
    username: 'Anonymous',
    publicKey: cryptico.publicKeyString($scope.privateKey)
  }
  $scope.me.publicKeyID = cryptico.publicKeyID($scope.me.publicKey);
  $scope.me.color = '#' + $scope.me.publicKeyID.substring(0, 6);

  $scope.users = [];
  $scope.messages = [];
  $scope.newMessage = { content: '' }

  $scope.addUser = function(newUser) {
    newUser.publicKeyID = cryptico.publicKeyID(newUser.publicKey);
    newUser.color = '#' + newUser.publicKeyID.substring(0, 6);
    $scope.users = $scope.users.filter(function(user) {
      return user.publicKey != newUser.publicKey;
    });
    $scope.users.push(newUser);
    $scope.$apply();
  }

  faye.subscribe('/users', function(newUser) {
    $scope.addUser(newUser);
    if ($scope.ready) {
      faye.publish('/users/' + newUser.publicKeyID + '/knockback', $scope.me);
    }
  });

  $scope.knock = function() {
    if ($scope.me.username == '') return;

    $scope.users = [];
    faye.publish('/users', $scope.me);

    faye.subscribe('/users/' + $scope.me.publicKeyID + '/knockback', function(newUser) {
      $scope.addUser(newUser);
    });

    faye.subscribe('/users/' + $scope.me.publicKeyID + '/messages', function(message) {
      decrypt = cryptico.decrypt(message.content, $scope.privateKey);
      message.content = $sce.trustAsHtml(emoji.replace_emoticons(emoji.replace_unified(sanitize(decrypt.plaintext))));
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
          console.log(decrypt);
        }
      } else {
        console.log(decrypt);
      }
    });

    $scope.ready = true;
  };

  $scope.sendMessage = function() {
    if ($scope.newMessage.content == '') return;

    $scope.newMessage.disabled = true;
    $scope.users.forEach(function(user) {
      message = Object.create($scope.newMessage);
      message.content = cryptico.encrypt(message.content, user.publicKey, $scope.privateKey).cipher;
      faye.publish('/users/' + user.publicKeyID + '/messages', message);
    });
    $scope.newMessage.content = '';
    $scope.newMessage.disabled = false;
  };
});
