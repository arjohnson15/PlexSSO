const sleep = async(timeout) => new Promise(resolve => window.setTimeout(resolve, timeout));

const PlexHeaders = {
    'Accept': 'application/json',
    'X-Plex-Product': 'PlexSSO',
    'X-Plex-Version': 'Plex OAuth',
    'X-Plex-Client-Identifier': 'PlexSSOv2'
};

class EventEmitter {
    constructor() {
        this._listeners = {};
    }

    on(event, callback) {
        if (!this._listeners[event]) {
            this._listeners[event] = new Set();
        }
        this._listeners[event].add(callback);
    }

    emit(event, ...data) {
        if (this._listeners[event]) {
            for (let listener of this._listeners[event]) {
                listener(...data);
            }
        }
    }
}

class PlexLoginWindow {
    constructor() {
        this._window = null;
    }

    show() {
        const width = window.innerWidth || document.documentElement.clientWidth || window.screen.width;
        const height = window.innerHeight || document.documentElement.clientHeight || window.screen.height;
        const left = ((width / 2) - 300) + (window.screenLeft || window.screenX);
        const top = ((height / 2) - 350) + (window.screenTop || window.screenY);
        this._window = window.open('', 'PlexSSO', `scrollbars=yes, width=${600}, height=${700}, top=${top}, left=${left}`);
        if (window.focus) {
            this._window.focus();
        }
    }

    hide() {
        if (this._window) {
            this._window.close();
        }
    }

    goTo(url) {
        if (this._window) {
            this._window.location = url;
        }
    }

    isHidden() {
        return this._window && this._window.closed;
    }
}

class PlexOAuth extends EventEmitter {
    constructor() {
        super();
        this._window = new PlexLoginWindow();
        this._loggedInStatus = null;
    }

    _setLoggedInStatus(status) {
        if (this._loggedInStatus !== status) {
            this._loggedInStatus = status;
            this.emit('loggedInStatus', status);
        }
    }

    async _getPlexToken() {
        try {
            this._window.show();

            const {pin, code} = await this._getPlexOAuthPin();
            this._window.goTo(`https://app.plex.tv/auth/#!?clientID=${PlexHeaders['X-Plex-Client-Identifier']}&code=${code}`);
            
            let token = null;
            while(true) {
                const response = await fetch(`https://plex.tv/api/v2/pins/${pin}`, {
                    headers: PlexHeaders
                });

                const jsonData = await response.json();
                if (jsonData.authToken || this._window.isHidden()) {
                    token = jsonData.authToken;
                    break;
                }
                await sleep(1000);
            }
            this._window.hide();
            return token;
        }
        catch(e) {
            this._window.hide();
            console.error(e);
            return null;
        }
    }

    async _getPlexOAuthPin() {
        const response = await fetch('https://plex.tv/api/v2/pins?strong=true', {
            method: 'POST',
            headers: PlexHeaders
        });
        const jsonData = await response.json();
        return {
            pin: jsonData.id,
            code: jsonData.code
        };
    }

    async _verifyToken(token) {
        const response = await fetch('/api/v2/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                token: token,
            })
        });
        return response.status < 400;
    }

    async login(rememberMe, existingToken = null) {
        const token = existingToken || await this._getPlexToken();
        if (!token || !await this._verifyToken(token)) {
            this._setLoggedInStatus(false);
            return false;
        }
        if (rememberMe) {
            localStorage.setItem('plex_token', token);
        }
        this._setLoggedInStatus(true);
        return true;
    }

    async logout() {
        await fetch('/api/v2/logout');
        localStorage.removeItem('plex_token');
        this._setLoggedInStatus(false);
    }

    async isLoggedIn() {
        if (this._loggedInStatus !== null) {
            return this._loggedInStatus;
        }

        const response = await fetch('/api/v2/sso');
        const json = await response.json();
        if (json.success) {
            this._setLoggedInStatus(true);
            return true;
        }

        // remember me
        const storedToken = localStorage.getItem('plex_token');
        if (!!storedToken) {
            return await this.login(true, storedToken);
        }

        this._setLoggedInStatus(false);
        return false;
    }
}

const singletonInstance = new PlexOAuth();
export default singletonInstance;
