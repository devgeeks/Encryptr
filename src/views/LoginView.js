(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _         = window._,
    $         = window.Zepto;

  var LoginView = Backbone.View.extend({
    el: "#login",
    events: {
      "submit form": "form_submitHandler",
      "click .loginButton": "loginButton_clickHandler",
      "click .signupButton": "signupButton_clickHandler"
    },
    initialize: function() {
      _.bindAll(this,
          "input_focusHandler",
          "input_blurHandler",
          "form_submitHandler",
          "loginButton_clickHandler",
          "signupButton_clickHandler");
      $(document).on("focus", "#login input", this.input_focusHandler);
      $(document).on("blur", "#login input", this.input_blurHandler);
    },
    render: function() {
      var _this = this;
      _this.signupView = new Encryptr.prototype.SignupView().render();
      _this.signupView.dismiss();
      window.setTimeout(function() {
        _this.signupView.$el.removeClass("hidden");
      }, 100);
      if (window.app.settings && window.app.settings.username) {
        $("#username").val(window.app.settings.username);
        $("#passphrase").focus();
      }
      return this;
    },
    input_focusHandler: function(event) {
      $(event.target).closest("div.login-input").addClass("focused");
    },
    input_blurHandler: function(event) {
      $(event.target).closest("div.login-input").removeClass("focused");
    },
    form_submitHandler: function(event) {
      var _this = this;
      event.preventDefault();

      $(".blocker").show();

      var username = $("#username").val().trim();
      var passphrase = $("#passphrase").val();

      $("input").blur();

      window.crypton.authorize(username, passphrase, function(err, session) {
        if (err) {
          navigator.notification.alert(
            "Username or Passphrase is incorrect",
            function() {},
            "Authentication error");
          $(".blocker").hide();
          return;
        }
        window.app.settings = _.extend(window.app.settings, {username: username});
        window.localStorage.setItem("settings", JSON.stringify(window.app.settings));
        window.app.session = session;
        var counterEstablished = $.Deferred();
        window.app.establishCounter(counterEstablished);
        window.app.accountModel = new window.app.AccountModel({
          username: username,
          passphrase: passphrase,
          session: session
        });
        window.app.mainView = new window.app.MainView().render();
        var entriesCollection = new window.app.EntriesCollection();
        window.app.navigator.pushView(
          window.app.EntriesView,
          { collection: entriesCollection },
          window.app.noEffect
        );
        _this.dismiss();
        $(".blocker").hide();
      });
    },
    loginButton_clickHandler: function(event) {
      event.preventDefault();
      this.form_submitHandler(event);
    },
    signupButton_clickHandler: function(event) {
      this.disable();
      this.signupView.show();
    },
    dismiss: function() {
      var _this = this;
      if (!_this.$el.hasClass("dismissed")) {
        // this.$("input").attr("disabled", true);
        _this.$el.animate({"-webkit-transform":"translate3d(0,100%,0)"}, 100, "ease-in-out", function() {
          _this.$el.addClass("dismissed");
        });
        // Clear username and password values
        _this.$("input").val("");
      }
    },
    show: function() {
      var _this = this;
      if (_this.$el.hasClass("dismissed")) {
        _this.$el.removeClass("dismissed");
        _this.$el.animate({"-webkit-transform":"translate3d(0,0,0)"}, {
          duration: 250,
          easing: "ease-in-out",
          complete: function() {
            if (window.app.settings && window.app.settings.username) {
              $("#username").val(window.app.settings.username);
              $("#passphrase").focus();
            }
          }
        });
      }
    },
    disable: function() {
      this.$("input").attr("disabled", true);
    },
    enable: function() {
      this.$("input").removeAttr("disabled");
    },
    which: "LoginView"
  });

  Encryptr.prototype.LoginView = LoginView;

})(this, this.console, this.Encryptr);
