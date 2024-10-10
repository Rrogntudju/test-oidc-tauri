const invoke = window.__TAURI__.core.invoke;

const userInfosViewModel = {
    propriétés: ko.observableArray( [
    //  { propriété: 'name', valeur : 'LOL' },
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

        await invoke("get_userinfos", { f: this.fournisseur() })
        .then((data) => {
            this.propriétés.removeAll();
            ko.utils.arrayPushAll(this.propriétés, JSON.parse(data));
        })
        .catch((error) => {
            console.log("Erreur Invoke: " + error);
            this.erreurInvoke(error);
        });

        this.enableUserInfos(true);
    }
}

ko.applyBindings(userInfosViewModel);
