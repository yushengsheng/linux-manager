"""Built-in v8 login contract shared by desktop and the embedded SSH bridge.

Vertex service-account JSON and configured API keys are imports, not callbacks.
Plugins remain owned by the official management page; unknown providers must not
be treated as built-ins or receive a guessed redirect URI.
"""
OAUTH_PROVIDERS = {
    'codex': {'label': 'Codex', 'flow': 'callback', 'port': 1455, 'path': '/auth/callback',
              'hosts': ('auth.openai.com',), 'redirect_host': 'localhost', 'tokens': ('access_token',)},
    'antigravity': {'label': 'Antigravity', 'flow': 'callback', 'port': 51121, 'path': '/oauth-callback',
                    'hosts': ('accounts.google.com',), 'redirect_host': 'localhost', 'tokens': ('access_token',)},
    'claude': {'label': 'Claude', 'flow': 'callback', 'port': 54545, 'path': '/callback',
               'hosts': ('claude.ai',), 'redirect_host': 'localhost', 'callback_provider': 'anthropic', 'tokens': ('access_token',)},
    'devin': {'label': 'Devin', 'flow': 'callback', 'port': None, 'path': '/callback',
              'hosts': ('app.devin.ai',), 'redirect_host': '127.0.0.1', 'tokens': ('session_token', 'api_key')},
    'kimi': {'label': 'Kimi 国内站', 'flow': 'api-device', 'port': 0, 'path': '',
             'hosts': ('auth.kimi.com', 'kimi.com', 'www.kimi.com'), 'tokens': ('access_token',)},
    'kimi-ai': {'label': 'Kimi 国际站', 'flow': 'api-device', 'port': 0, 'path': '',
                'hosts': ('auth.kimi.ai', 'kimi.ai', 'www.kimi.ai'), 'tokens': ('access_token',)},
    'xai': {'label': 'xAI', 'flow': 'api-device', 'port': 0, 'path': '',
            'hosts': ('auth.x.ai', 'accounts.x.ai'), 'tokens': ('access_token',)},
    'meta': {'label': 'Muse (Meta)', 'flow': 'api-device', 'port': 0, 'path': '',
             'hosts': ('auth.meta.com',), 'tokens': ('access_token', 'dca_token', 'api_key')},
}
