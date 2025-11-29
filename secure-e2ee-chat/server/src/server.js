const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { connectDB } = require('./config/db');
const authRoutes = require('./routes/authRoutes');
const keyExchangeRoutes = require('./routes/keyExchangeRoutes');
const messageRoutes = require('./routes/messageRoutes');
const fileRoutes = require('./routes/fileRoutes');
const auditRoutes = require('./routes/auditRoutes');
const { errorHandler } = require('./middleware/errorHandler');

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json({ limit: '50mb' }));

connectDB();

app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/keyexchange', keyExchangeRoutes);
app.use('/api/v1/messages', messageRoutes);
app.use('/api/v1/files', fileRoutes);
app.use('/api/v1/audit', auditRoutes);

app.use(errorHandler);

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});


