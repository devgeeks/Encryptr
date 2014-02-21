/* Some crypton conveniences */
if (window.crypton) {
  window.cryptonutils = {
    /** Establish a container in a holder, creating it if not already created.
     *
     * @param {string} name for the container
     * @param {object} session crypton session object for the container
     * @param {callable} success invoked with obtained container
     * @param {callable} error invoked with create error message, if all fail
     */
    loadOrCreateContainer: function(name, session, success, error) {
      session.load(name, function(err, container) {
        if (!err) {
          if (success) {
            success(container);
          }
        }
        else {
          session.create(name, function(err, container) {
            if (err) {
              if (error) {
                error(err);
              }
            }
            else {
              if (success) {
                success(container);
              }
            }
          });
        }
      });
    },
    /** Get current value of key in container, or else create with value.
     *
     * @param {object} container crypton container for the setting
     * @param {string} key within the container that gets the assignment
     * @param {object} value to assign to key *iff* key is not already present
     * @param {callable} success invoked with obtained value
     * @param {callable} error invoked with error msg
     */
    getOrCreateSetting: function(container, key, value, success, error) {
      container.get(key, function (err, got) {
        if (! err) {
          success(got);
        }
        else {
          container.add(key, function (err) {
            if (err) {
              error("Failed to add or get '" + key + "': " + err);
            }
            else {
              container.keys[key] = value;
              container.save(function (err) {
                if (err) {
                  error("Failed to save '" + key + "': " + err);
                }
                else {
                  success(value);
                }
              });
            }
          });
        }
      });
    }
  };
}
