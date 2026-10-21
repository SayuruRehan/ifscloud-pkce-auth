import { app } from './app.js';
import { config } from './config.js';

app.listen(config.port, () => {
  console.log(`IFS Cloud PKCE demo on http://localhost:${config.port}`);
  console.log(`Issuer:       ${config.issuer}`);
  console.log(`Client ID:    ${config.clientId} (${config.clientSecret ? 'confidential' : 'public'})`);
  console.log(`Redirect URI: ${config.redirectUri}`);
});
