const { invoke } = window.__TAURI__.tauri;

  const userInfosViewModel = {
    propriétés: ko.observableArray( [
      // { propriété: 'name', valeur : 'LOL' },
    ]),

    fournisseur: ko.observable("Microsoft"),

    clicFournisseur : function() {
        this.propriétés.removeAll();
        return true;
    },

    enableUserInfos: ko.observable(true),

    erreurInvoke: ko.observable(""),

    getUserInfos: async function() {
        this.enableUserInfos(false);
        this.erreurInvoke("");

        await invoke("get_userinfos", { fournisseur: this.fournisseur })
        .then((data) => {
            this.propriétés.removeAll();
            ko.utils.arrayPushAll(this.propriétés, data.propriétés);
        })
        .catch((error) => {
            console.log("Erreur Invoke: " + error);
            this.erreurInvoke(error);
            this.enableUserInfos(true);
        });
    }
}

ko.applyBindings(userInfosViewModel);
