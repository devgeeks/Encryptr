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
      var typeModel = $(event.target).data("model"),
          model;
      if (typeModel === "FolderModel") {
        model = new window.app.FolderModel();
      }
      else {
        model = new window.app.EntryModel(new window.app.types[typeModel]());
      }
      model.container = window.app.currentEntriesCollection.container;
      window.app.navigator.pushView(window.app.EditView, {
        model: model
      }, window.app.defaultEffect);
    },
    dismiss: function() {
      if (!this.$el.hasClass("dismissed")) {
        var _this = this;
        this.$("input").attr("disabled", true);
        this.$el.animate({
          "-webkit-transform":"scale3d(0.8,0.8,0.8) translate3d(10%,-10%,0)",
          "opacity":"0"
        }, 100, "ease-in-out", function() {
          _this.$el.addClass("dismissed");
        });
      }
    },
    show: function() {
      if (this.$el.hasClass("dismissed")) {
        this.$el.removeClass("dismissed");
        this.$("input").removeAttr("disabled");
        this.$el.animate({
          "-webkit-transform":"scale3d(1,1,1) translate3d(0,0,0)",
          "opacity":"1"
        }, 100, "ease-in-out");
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
