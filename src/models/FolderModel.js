// FolderModel.js
(function (window, console, Encryptr, undefined) {
  "use strict";
  console       = console || {};
  console.log   = console.log || function() {};
  var Backbone  = window.Backbone,
    _         = window._,
    $         = window.Zepto;

  /** FolderModel has features of an entry type, but is a real model. */
  var FolderModel = Backbone.Model.extend({
    defaults: {
      contentsId: null,
      type: "Folder"
    },
    displayName: "Folder",
    collection: Encryptr.prototype.EntriesCollection,
    contents: null,
    initialize: function () {
      // XXX Probably should remove "folder:", to reduce server-exposed info.
      this.modelId = "folder:" + window.app.getNewUnique();
      this.contents = null;
    },
    /** Intervene in save to create our contents container, if we lack it. */
    save: function (attrs, options) {
      var thisFolder = this;
      if (! thisFolder.contents) {
        var collection = new Encryptr.prototype.EntriesCollection();
        collection.model = FolderModel;
        collection.modelId = "folderCollection:" + window.app.getNewUnique();
        collection.container = collection.modelId;
        thisFolder.contents = collection;
        thisFolder.set("contentsId", collection.container);
        var got = window.app.session.create(
          collection.container,
          function (err, container) {
            Backbone.Model.prototype.save.call(thisFolder, attrs, options);
          });
      }
      else {
        Backbone.Model.prototype.save.call(thisFolder, attrs, options);
      }
    },
    fetch: function (options) {
      /* Reconstitute our entry collection if what we have is just the ID. */
      if (! this.contents) {
        var contentsId = this.get("contentsId");
        var collection = new Encryptr.prototype.EntriesCollection();
        collection.container = contentsId;
        this.contents = collection;
        collection.fetch({
          error: function(errmsg) {
            navigator.notification.alert(
              "Fetch: " + errmsg,
              function() {},
              "Error");
          }
        });
      }
    },
    which: "FolderModel"
  });

  Encryptr.prototype.FolderModel = FolderModel;

  Encryptr.prototype.types = Encryptr.prototype.types || {};
  Encryptr.prototype.types.FolderModel = FolderModel;

})(this, this.console, this.Encryptr);
