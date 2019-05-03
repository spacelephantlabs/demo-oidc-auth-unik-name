This the source code of Unik-Name OpenID Connect demo application.

# Instructions

To install this example on your computer, clone the repository and install
dependencies.

```bash
$ git clone git@github.com:spacelephantlabs/demo-oidc-auth-unik-name.git
$ cd demo-oidc-auth-unik-name
$ npm install
```

# Running the application

## In development

```bash
$ node server.js
```

The application is configured to look for the Unik-Name Authentication server on `http://localhost:8080/`.

Open a web browser and navigate to [http://localhost:3003/](http://127.0.0.1:3003/)
to see the example in action.

## In other environments

```bash
$ NODE_ENV=myenv node server.js
```

where `myenv` can be:
- `integ` for "integration" environment

Each environment must be configured in its own `.env.myenv` file (see [.env](.env) or [.env.integ](.env.integ) files).
