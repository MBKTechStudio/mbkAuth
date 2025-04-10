# mbkAuth
mbkAuth is an npm package designed to simplify authentication workflows in your Node.js applications. It provides a set of tools and utilities to handle user authentication, token management, and session handling with ease.

## Features

- Easy integration with popular frameworks like Express.
- Support for JWT-based authentication.
- Middleware for protecting routes.
- Configurable token expiration and secret management.
- Lightweight and extensible.

## Installation

Install the package using npm:

```bash
npm install mbkauth
```

## Usage

Here is a basic example of how to use mbkAuth in an Express application:

```javascript
const express = require('express');
const mbkAuth = require('mbkauth');

const app = express();
const auth = mbkAuth({
    secret: 'your-secret-key',
    tokenExpiration: '1h',
});

app.use(express.json());

// Public route
app.get('/', (req, res) => {
    res.send('Welcome to mbkAuth!');
});

// Protected route
app.get('/protected', auth.protect, (req, res) => {
    res.send('This is a protected route.');
});

// Start the server
app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
```

## Configuration

You can configure mbkAuth by passing an options object during initialization:

- `secret` (required): The secret key used for signing tokens.
- `tokenExpiration` (optional): The duration for which tokens are valid (e.g., '1h', '30m').

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.