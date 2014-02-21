(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _         = window._,
    $         = window.Zepto;

  var SignupView = Backbone.View.extend({
    className: "signup hidden",
    events: {
      "submit form": "form_submitHandler",
      "click .signupButton": "signupButton_clickHandler",
      "click a.backToLogin": "backToLogin_clickHandler"
    },
    initialize: function() {
      _.bindAll(this,
          "input_focusHandler",
          "input_blurHandler",
          "form_submitHandler",
          "signupButton_clickHandler",
          "backToLogin_clickHandler");
      $(document).on("focus", ".signup input", this.input_focusHandler);
      $(document).on("blur", ".signup input", this.input_blurHandler);
    },
    render: function() {
      this.$el.html(window.tmpl["signupView"]({}));
      $(".app").append(this.el);
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

      var username = $("#newusername").val().trim();
      var passphrase = $("#newpassphrase").val();

      $("input").blur();

      window.crypton.generateAccount(username, passphrase, function(err, account) {
        if (err) {
          navigator.notification.alert(
            err,
            function() {},
            "Signup error");
          $(".blocker").hide();
          return;
        }
        // Now log in...
        window.crypton.authorize(username, passphrase, function(err, session) {
          if (err) {
            navigator.notification.alert(
              err,
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
          var rcID = window.app.EntriesCollection.prototype.rootContainerID;
          counterEstablished.done(function () {
            window.app.session.create(rcID, function(err, entries){
              if (err) {
                navigator.notification.alert(err);
                $(".blocker").hide();
                return;
              }
              // Set up MainView
              window.app.mainView = new window.app.MainView().render();
              // Push an EntriesView
              window.app.navigator.pushView(
                window.app.EntriesView,
                { collection: new window.app.EntriesCollection() },
                window.app.noEffect
              );
              $(".blocker").hide();
              window.app.loginView.dismiss();
              _this.dismiss();
            });
          });
        });
      });
    },
    signupButton_clickHandler: function(event) {
      event.preventDefault();
      this.form_submitHandler(event);
    },
    backToLogin_clickHandler: function(event) {
      // window.app.loginView.show();
      window.app.loginView.enable();
      this.dismiss();
    },
    dismiss: function() {
      var _this = this;
      if (!_this.$el.hasClass("dismissed")) {
        _this.$("input").attr("disabled", true);
        _this.$el.animate({"-webkit-transform":"translate3d(0,100%,0)"}, 100, "ease-in-out", function() {
          _this.$el.addClass("dismissed");
        });
        // Clear username and password values
        this.$("input").val("");
      }
    },
    show: function() {
      var _this = this;
      if (_this.$el.hasClass("dismissed")) {
        _this.$("input").removeAttr("disabled");
        _this.$el.removeClass("dismissed");
        _this.$el.animate({"-webkit-transform":"translate3d(0,0,0)"}, 250, "ease-in-out");
      }
    },
    which: "SignupView"
  });

  Encryptr.prototype.SignupView = SignupView;

})(this, this.console, this.Encryptr);
