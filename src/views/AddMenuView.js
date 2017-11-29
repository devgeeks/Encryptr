(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _         = window._,
    $         = window.Zepto;

  var AddMenuView = Backbone.View.extend({
    className: "addMenu",
    events: {
      "click a": "a_clickHandler"
    },
    initialize: function() {
      _.bindAll(this, "a_clickHandler");
    },
    render: function() {
      this.$el.html(window.tmpl["addMenuView"]({
        types: Encryptr.prototype.types
      }));
      return this;
    },
    a_clickHandler: function(event) {
      event.stopPropagation();
      event.preventDefault();
      this.dismiss();
      var typeModel = $(event.target).data("model") ||
        $(event.target).closest('a').data('model');
      if (!typeModel) return;
      $(".fab").addClass("shrunken");
      window.app.navigator.pushView(window.app.EditView, {
        model: new window.app.EntryModel(
          new window.app.types[typeModel]()
        )
      }, window.app.defaultEffect);
    },
    dismiss: function() {
      if (!this.$el.hasClass("dismissed")) {
        var _this = this;
        this.$("input").attr("disabled", true);
        $(".subviews, .nav").removeClass("less");
        $(".subviews").attr("style", "-webkit-overflow-scrolling: touch;");
        this.$el.animate("addMenuHide", 200, "ease-out", function() {
          _this.$el.addClass("dismissed");
        });
      }
    },
    show: function() {
      if (this.$el.hasClass("dismissed")) {
        this.$el.removeClass("dismissed");
        this.$("input").removeAttr("disabled");
        $(".subviews, .nav").addClass("less");
        this.$el.animate("addMenuShow", 200, "ease-in-out");
      }
    },
    toggle: function() {
      if (this.$el.hasClass("dismissed")) {
        this.show();
      } else {
        this.dismiss();
      }
    },
    close: function() {
      this.remove();
    }
  });

  Encryptr.prototype.AddMenuView = AddMenuView;

})(this, this.console, this.Encryptr);
