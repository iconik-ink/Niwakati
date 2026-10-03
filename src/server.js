import app from './app.js';
import { config } from './config.js';
import { startExpiryJob } from './jobs/expireAccess.js';

app.listen(config.port, () => {
  console.log(`API + site listening on :${config.port}`);
  startExpiryJob();
});
