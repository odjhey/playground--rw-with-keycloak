## Auth Notes


- token refresh of client/web happens here?
https://github.com/redwoodjs/redwood/blob/v3.5.0/packages/web/src/apollo/index.tsx#L117
https://github.com/redwoodjs/redwood/blob/v3.5.0/packages/auth/src/AuthProvider.tsx#L247

- client implementation can be found here
https://github.com/redwoodjs/redwood/blob/v3.5.0/packages/auth/src/authClients/dbAuth.ts
note that v3.5.0 has this, but recent commits looks like its gonna move to a more generic solution
