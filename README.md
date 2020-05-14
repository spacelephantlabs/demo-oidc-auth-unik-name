This is the source code of Unik-Name OpenID Connect demo application integrating auth0 with Unikname Connect application

# Instructions

To install this example on your computer, clone the repository and install
dependencies.

```bash
$ yarn install
```

# Running the application

## In development

```bash
$ node server.js
```

The application is configured to look for the Unik-Name Authentication server on `http://localhost:8080/`.

Open a web browser and navigate to http://localhost:3003/ to see the example in action.

**NOTE**: as routing between tenants is done with domain names, you mustn't load the application in your browser with use IP addresses.

## In other environments

```bash
$ NODE_ENV=myenv node server.js
```

where `myenv` can be:
- `integ` for "integration" environment

Each environment must be configured in its own `.env.myenv` file (see [.env](.env) or [.env.integ](.env.integ) files).

## 📝 License

Copyright © 2019 [Space Elephant](https://github.com/spacelephant).<br />
This project is [MIT](LICENSE) licensed.
