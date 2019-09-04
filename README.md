This the source code of Unik-Name OpenID Connect demo application.

# Instructions

To install this example on your computer, clone the repository and install
dependencies.

```bash
$ npm install
```

# Running the application

## In development

```bash
$ node server.js
```

The application is configured to look for the Unik-Name Authentication server on `http://localhost:8080/`.

Open a web browser and navigate to http://localhost:3003/ to see the example in action.

**NOTE**: as routing between tenants is done with domain names, you mustn't load the application in your browser with use IP addresses.

### Platform choice

In order to simulate the multiple `10x` websites, (eg: `www.platform101.net`, `www.platform101.net` ...), you have to choose the launching "mode" of the application.
Please change `DEV_PORT` and `P10*_HOST_URL` environment variables values in `.env` file

Default mode, for Platform101 mode:
```
DEV_PORT=3003
P101_HOST_URL=localhost:3003
P102_HOST_URL=localhost:3004
```

To configure for Platform102 mode:
```
DEV_PORT=3004
P101_HOST_URL=localhost:3003
P102_HOST_URL=localhost:3004
```

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
