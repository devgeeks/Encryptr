(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _         = window._,
    $         = window.Zepto;

  /**
   * Settings view. From here select individual settings pages
   */
  var SettingsView = Backbone.View.extend({
    destructionPolicy: "never",
    events: {
      "click .logout-button": "logout_clickHandler",
      "click .contact-spideroak": "feedback_clickHandler",
      "click .change-passphrase": "changePassphrase_clickHandler"
    },
    initialize: function () {
      _.bindAll(this, "render", "logout_clickHandler");
      app.checkonline(['.change-passphrase', '.btn.save-btn']);
      this.on("viewActivate",this.viewActivate);
      this.on("viewDeactivate",this.viewDeactivate);
      this.settingsHaveChanged = false;
    },
    render: function () {
      this.$el.html(window.tmpl["settingsView"]({}));
      return this;
    },
    changePassphrase_clickHandler: function(event) {
      event.preventDefault();
      if (window.online) {
        window.app.navigator.pushView(window.app.PassphraseSettingsView, {
          model: window.app.accountModel
        }, window.app.defaultEffect);
      } else {
        window.app.toastView.show("While your device is offline you can't change your passphrase");
      }
    },
    logout_clickHandler: function(event) {
      event.preventDefault();
      window.sessionStorage.clear();
      if (window.app.logoutInterval) {
        window.clearInterval(window.app.logoutInterval);
      }
      window.app.accountModel.logout(function() {
        window.app.accountModel = new window.app.AccountModel();
        window.app.loginView.disable();
        // Throw up the login screen
        window.app.loginView.show();
        window.setTimeout(function() {
          if (window.app.navigator.viewsStack.length > 0) {
            window.app.navigator.popAll(window.app.noEffect);
          }
          window.app.mainView.close();
        },100);
        window.setTimeout(function() {
          window.app.loginView.enable();
        },350);
      });
    },
    feedback_clickHandler: function(event) {
      event.preventDefault();
      var feedbackUrl = "https://spideroak.com/solutions/encryptr/feedback";
      if (window.cordova.InAppBrowser) {
        window.cordova.InAppBrowser.open(feedbackUrl, '_system');
      } else if ($.os.isNodeWebkit) {
        var gui = window.require('nw.gui');
        gui.Shell.openExternal(feedbackUrl);
      } else {
        // browser fallback
        window.open(feedbackUrl, '_blank');
      }
    },
    viewActivate: function(event) {
      $('.subviews').scrollTop(0);
      window.app.mainView.backButtonDisplay(true);
      $(".nav .btn.right").addClass("hidden");
      $(".nav .add-btn.right").addClass("hidden");
      window.app.mainView.setTitle("Settings");
    },
    viewDeactivate: function(event) {
      // ...
    },
    close: function() {
      this.remove();
    }
  });

  Encryptr.prototype.SettingsView = SettingsView;

  var PassphraseSettingsView = Backbone.View.extend({
    destructionPolicy: "never",
    events: {
      "change #show-new-passphrase": "showPassphrase_changeHandler",
      "submit form": "form_submitHandler"
    },
    initialize: function () {
      _.bindAll(this, "render", "form_submitHandler", "viewActivate",
        "viewDeactivate", "showPassphrase_changeHandler");
      this.on("viewActivate",this.viewActivate);
      this.on("viewDeactivate",this.viewDeactivate);
      this.confirmBackNav = {
        title: "You have unsaved changes",
        subtitle: "Go back and discard any changes?",
        callback: function() {
          window.app.toastView.show("Changes discarded.");
        }
      };
      if (!window.app.toastView) {
        window.app.toastView = new window.app.ToastView();
      }
    },
    render: function () {
      this.$el.html(window.tmpl["passphraseSettingsView"]({}));
      window.app.mainView.on("saveentry", this.form_submitHandler, this);
      return this;
    },
    showPassphrase_changeHandler: function(event) {
      var $newpassphrases = this.$('input[name^="passphrase-new"]');
      $newpassphrases.each(function() {
        var $this = $(this);
        var newType = (($this.attr("type") === "password") ? "text" : "password");
        $this.attr("type", newType);
      });
    },
    form_submitHandler: function(event) {
      var _this = this;
      if (event) event.preventDefault();

      // Form validation
      var $passphraseCurrent = _this.$('input[name="passphrase-current"]');
      var $passphraseNew1 = _this.$('input[name="passphrase-new1"]');
      var $passphraseNew2 = _this.$('input[name="passphrase-new2"]');
      var passphraseCurrent = $passphraseCurrent.val();
      var passphraseNew = $passphraseNew1.val();
      var passphraseNewConfirm = $passphraseNew2.val();

      _this.$('input[type="text"], input[type="password"]').removeClass("error");
      if (!$passphraseCurrent.val() || !$passphraseNew1.val() ||
          !$passphraseNew2.val()) {
        window.app.toastView.show("All fields required");
        _this.$('input[type="text"], input[type="password"]').each(function() {
          if (!$(this).val()) {
            $(this).addClass("error");
          }
        });
        return;
      }

      if (passphraseCurrent !== window.app.accountModel.get("passphrase")) {
        window.app.toastView.show("Passphrase incorrect");
        _this.$('input[name="passphrase-current"]').addClass("error");
        return;
      }

      if (passphraseNew !== passphraseNewConfirm) {
        window.app.toastView.show("New passphrases do not match");
        _this.$('input[name^="passphrase-new"]').addClass("error");
        return;
      }
      // End form validation

      $("input").blur();

      // Pop up a dialog to warn about how serious this is
      window.app.dialogConfirmView.show({
        title: "Warning - Changing Passphrase",
        subtitle: "If you forget your new passphrase your account will be unrecoverable! Continue?",
        callback: function() {
          window.app.toastView.show("Passphrase unchanged");
        }
      }, function(event) {
        if (event.type !== "dialogAccept") {
          return;
        } else {
          $(".blocker").show();

          // 1. change passphrase using app.session.account.changePassphrase()
          window.app.session.account.changePassphrase(passphraseCurrent,
              passphraseNew, function changePassphraseCallback(err, success) {
            if (err) {
              // Password remains unchanged in this case
              window.app.toastView.show("Passphrase unchanged");
              window.app.dialogAlertView.show({
                title: "Error",
                subtitle: err
              }, function() {
                $(".blocker").hide();
              });
              return;
            }

            // 2. update the window.app.accountModel passphrase
            window.app.toastView.show("Success");
            window.app.accountModel.set("passphrase", passphraseNew);

            // 3. remove and re-add/re-encrypt the localStorage cache using the
            //    new passphrase
            var username = window.app.accountModel.get("username");
            var hashArray = window.sjcl.hash.sha256.hash(username);
            var hash = window.sjcl.codec.hex.fromBits(hashArray);
            window.localStorage.removeItem("encryptr-" + hash + "-index");
            var indexJSON = JSON.stringify(window.app.entriesCollection.toJSON());
            if (window.app.accountModel.get("passphrase")) {
              var encryptedIndexJSON = window.sjcl.encrypt(
                window.app.accountModel.get("passphrase"), indexJSON,
                window.crypton.cipherOptions
              );
              window.localStorage.setItem("encryptr-" + hash + "-index",
                encryptedIndexJSON);
            }

            // 4. reauth with the new passphrase to update sessions etc
            window.app.toastView.show("Logging in with new passphrase");
            window.crypton.authorize(window.app.accountModel.get("username"),
                window.app.accountModel.get("passphrase"), function(err, session) {
              if (err) {
                // At this point the password is successfully changed
                // We just haven't been able to renew the session
                // LOG OUT!!!! (for safety, ya know...)
                $(document).trigger("logout");
                window.app.toastView.show("Error renewing session.<br/>" +
                  "Log in with your new passphrase", 3000);
                window.app.dialogAlertView.show({
                  title: "Error",
                  subtitle: err
                }, function() {
                  $(".blocker").hide();
                });
                console.log(new Error(err).stack);
                return false;
              }

              window.app.session = session;
              window.app.accountModel = new window.app.AccountModel({
                username: session.account.username,
                passphrase: session.account.passphrase,
                session: session
              });
              Backbone.Session = session;

              window.app.navigator.popView(window.app.defaultPopEffect);
              $(".blocker").hide();
              window.app.toastView.show("Passphrase changed", 3000);
              window.app.session.getContainer('_encryptrIndex', function(err, container) {
                window.app.mainView.updatedLocalStorage = false;
                window.app.mainView.updateLocalStorage();
              });
            });
          }, function() {
            window.app.toastView.show("Starting passphrase keygen");
          });
        }
      });
    },
    viewActivate: function(event) {
      window.app.mainView.backButtonDisplay(true);
      $(".nav .btn.right").addClass("hidden");
      $(".nav .add-btn.right").addClass("hidden");
      $(".nav .save-btn").removeClass("hidden");
      window.app.mainView.setTitle("Passphrase");
    },
    viewDeactivate: function(event) {
      window.app.mainView.off("saveentry", this.form_submitHandler, this);
    },
    close: function() {
      this.remove();
    }
  });

  Encryptr.prototype.PassphraseSettingsView = PassphraseSettingsView;

})(this, this.console, this.Encryptr);
