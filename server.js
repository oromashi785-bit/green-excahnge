const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const USERS_FILE = path.join(__dirname, 'users.json');
const sessions = new Map();
const IS_SERVERLESS = Boolean(process.env.VERCEL);
const MONGODB_URI = process.env.MONGODB_URI;
const MONGODB_DB = process.env.MONGODB_DB || 'exchange_walletst_app';
let mongoClient;
let usersCollection;
let sessionsCollection;
let userStoreReadyPromise;

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, expectedHex] = stored.split(':');
  const actual = crypto.scryptSync(String(password), salt, 64);
  const expected = Buffer.from(expectedHex, 'hex');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) {
    const initial = [{
      id: crypto.randomUUID(),
      username: process.env.ADMIN_USERNAME || 'admin',
      passwordHash: hashPassword(process.env.ADMIN_PASSWORD || 'admin123'),
      role: 'admin',
      expiresAt: null,
      createdAt: new Date().toISOString()
    }];
    if (!IS_SERVERLESS) fs.writeFileSync(USERS_FILE, JSON.stringify(initial, null, 2));
    return initial;
  }
  const storedUsers = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  let migrated = false;
  for (const user of storedUsers) {
    if (user.password && !user.passwordHash) {
      user.passwordHash = hashPassword(user.password);
      delete user.password;
      migrated = true;
    }
  }
  if (migrated) fs.writeFileSync(USERS_FILE, JSON.stringify(storedUsers, null, 2));
  return storedUsers;
}

let users = MONGODB_URI ? [] : loadUsers();

async function initialiseUserStore() {
  if (!MONGODB_URI) {
    if (IS_SERVERLESS) throw new Error('MONGODB_URI is required in the Vercel environment.');
    return;
  }

  mongoClient = new MongoClient(MONGODB_URI);
  await mongoClient.connect();
  usersCollection = mongoClient.db(MONGODB_DB).collection('users');
  sessionsCollection = mongoClient.db(MONGODB_DB).collection('sessions');
  await usersCollection.createIndex({ username: 1 }, { unique: true });
  await sessionsCollection.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  users = await usersCollection.find({}).toArray();

  if (users.length === 0) {
    const username = String(process.env.ADMIN_USERNAME || '').trim();
    const password = String(process.env.ADMIN_PASSWORD || '');
    if (!username || password.length < 8) {
      throw new Error('Set ADMIN_USERNAME and an ADMIN_PASSWORD of at least 8 characters before the first deployment.');
    }
    const admin = {
      id: crypto.randomUUID(), username, passwordHash: hashPassword(password),
      role: 'admin', expiresAt: null, createdAt: new Date().toISOString()
    };
    await usersCollection.insertOne(admin);
    users = [admin];
  }
}

function ensureUserStore() {
  userStoreReadyPromise ??= initialiseUserStore();
  return userStoreReadyPromise;
}

const saveUsers = async () => {
  if (usersCollection) {
    await usersCollection.deleteMany({});
    if (users.length) await usersCollection.insertMany(users);
  } else if (!IS_SERVERLESS) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  }
};
const publicUser = (user) => ({ id:user.id, username:user.username, role:user.role, expiresAt:user.expiresAt });
const adminUser = (user) => ({ ...publicUser(user), createdAt:user.createdAt, password:'••••••••' });

app.use('/api', async (req, res, next) => {
  try {
    await ensureUserStore();
    next();
  } catch (error) {
    console.error('User store initialisation failed:', error.message);
    res.status(503).json({ error: 'The account service is not configured yet.' });
  }
});

async function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const session = sessionsCollection ? await sessionsCollection.findOne({ token }) : sessions.get(token);
  const user = session && users.find((entry) => entry.id === session.userId);
  if (!user || (user.expiresAt && Date.now() >= user.expiresAt)) {
  if (token) {
    sessions.delete(token);
    if (sessionsCollection) await sessionsCollection.deleteOne({ token });
  }
    return res.status(401).json({ error:'Session expired or unauthorized' });
  }
  req.authUser = user;
  req.authToken = token;
  next();
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => req.authUser.role === 'admin' ? next() : res.status(403).json({ error:'Admin access required' }));
}

app.post('/api/login', async (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const user = users.find((entry) => entry.username.toLowerCase() === username.toLowerCase() && verifyPassword(password, entry.passwordHash));
  if (!user) return res.status(401).json({ error:'Incorrect username or password' });
  if (user.expiresAt && Date.now() >= user.expiresAt) return res.status(403).json({ error:'Your access time has expired. Contact the admin.' });
  if (sessionsCollection) await sessionsCollection.deleteMany({ userId: user.id });
  else for (const [existingToken, session] of sessions) if (session.userId === user.id) sessions.delete(existingToken);
  const token = crypto.randomBytes(32).toString('hex');
  const session = { token, userId:user.id, createdAt:new Date(), expiresAt:new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) };
  sessions.set(token, session);
  if (sessionsCollection) await sessionsCollection.insertOne(session);
  res.json({ token, user:publicUser(user) });
});

app.get('/api/session', requireAuth, (req, res) => res.json({ user:publicUser(req.authUser) }));
app.post('/api/logout', requireAuth, async (req, res) => {
  sessions.delete(req.authToken);
  if (sessionsCollection) await sessionsCollection.deleteOne({ token: req.authToken });
  res.json({ ok:true });
});

app.get('/api/admin/users', requireAdmin, (req, res) => {
  res.json(users.filter((user) => user.role !== 'admin').map(adminUser));
});

app.post('/api/admin/users', requireAdmin, async (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '').trim();
  const durationMs = Number(req.body.durationMs);
  if (!/^[A-Za-z0-9._-]{3,32}$/.test(username) || password.length < 4 || durationMs < 60000) return res.status(400).json({ error:'Enter a valid username, password, and access time' });
  if (users.some((user) => user.username.toLowerCase() === username.toLowerCase())) return res.status(409).json({ error:'Username already exists' });
  const user = { id:crypto.randomUUID(), username, passwordHash:hashPassword(password), role:'user', expiresAt:Date.now()+durationMs, createdAt:new Date().toISOString() };
  users.push(user); await saveUsers(); res.status(201).json(adminUser(user));
});

app.put('/api/admin/users/:id', requireAdmin, async (req, res) => {
  const user = users.find((entry) => entry.id === req.params.id && entry.role !== 'admin');
  if (!user) return res.status(404).json({ error:'User not found' });
  if (req.body.username !== undefined) user.username = String(req.body.username).trim();
  if (req.body.password !== undefined && String(req.body.password).trim()) user.passwordHash = hashPassword(String(req.body.password).trim());
  if (req.body.adjustMs !== undefined) user.expiresAt = Math.max(Date.now(), Number(user.expiresAt || Date.now()) + Number(req.body.adjustMs));
  if (req.body.expiresAt !== undefined) user.expiresAt = Number(req.body.expiresAt);
  await saveUsers(); res.json(adminUser(user));
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  const before = users.length;
  users = users.filter((entry) => !(entry.id === req.params.id && entry.role !== 'admin'));
  if (users.length === before) return res.status(404).json({ error:'User not found' });
  await saveUsers(); res.json({ ok:true });
});

const browserHeaders = {
  'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  'Accept-Language': 'en-US,en;q=0.9'
};
const profileCache = new Map();
const unavailableProfileCache = new Map();
const PROFILE_CACHE_TTL_MS = 60 * 1000;
const UNAVAILABLE_PROFILE_CACHE_TTL_MS = 2 * 60 * 1000;
const FALLBACK_TIKTOK_AVATAR = '/assets/pfpwhite.png';

function fallbackTikTokProfile(username) {
  return {
    unique_id: username,
    nickname: username,
    avatar: FALLBACK_TIKTOK_AVATAR,
    follower_count: null,
    following_count: null,
    is_fallback: true,
    is_private_or_unavailable: true
  };
}

function logLookupFailure(source, error) {
  if (process.env.DEBUG_TIKTOK_LOOKUP === '1') console.warn(`${source}:`, error.message);
}

function readJsonScript(html, id) {
  const marker = `id="${id}"`;
  const markerIndex = html.indexOf(marker);
  if (markerIndex === -1) return null;
  const start = html.indexOf('>', markerIndex) + 1;
  const end = html.indexOf('</script>', start);
  if (!start || end === -1) return null;

  try {
    return JSON.parse(html.slice(start, end));
  } catch {
    return null;
  }
}

function readMeta(html, property) {
  const escaped = property.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const patterns = [
    new RegExp(`<meta[^>]+property=["']${escaped}["'][^>]+content=["']([^"']*)["']`, 'i'),
    new RegExp(`<meta[^>]+content=["']([^"']*)["'][^>]+property=["']${escaped}["']`, 'i'),
    new RegExp(`<meta[^>]+name=["']${escaped}["'][^>]+content=["']([^"']*)["']`, 'i')
  ];
  const value = patterns.map((pattern) => html.match(pattern)?.[1]).find(Boolean);
  return value?.replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;/g, "'") || '';
}

function parseCountFromText(text) {
  if (!text) return null;
  const match = text.match(/([\d.,]+[KMBkmb]?)\s*(Followers|Following|Likes)?/i);
  if (!match) return null;
  let str = match[1].toUpperCase();
  let mult = 1;
  if (str.endsWith('K')) { mult = 1000; str = str.slice(0, -1); }
  else if (str.endsWith('M')) { mult = 1000000; str = str.slice(0, -1); }
  else if (str.endsWith('B')) { mult = 1000000000; str = str.slice(0, -1); }
  const num = parseFloat(str.replace(/,/g, ''));
  return isNaN(num) ? null : Math.round(num * mult);
}

function firstCount(...values) {
  for (const value of values) {
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    if (typeof value === 'string') {
      const parsed = parseCountFromText(value);
      if (parsed !== null) return parsed;
    }
  }
  return null;
}

function normaliseTikTokUser(rawUser, rawStats = {}) {
  if (!rawUser) return null;
  const stats = rawUser.stats || rawUser.statistics || rawStats || {};
  const uniqueId = rawUser.uniqueId || rawUser.unique_id || rawUser.username || rawUser.handle_name;
  if (!uniqueId) return null;

  return {
    unique_id: uniqueId,
    nickname: rawUser.nickname || rawUser.display_name || rawUser.handle_name || uniqueId,
    avatar: rawUser.avatarLarger || rawUser.avatarMedium || rawUser.avatarThumb || rawUser.avatar || rawUser.avatar_url || rawUser.avatarUrl || rawUser.avatar_larger?.url_list?.[0] || rawUser.avatar_medium?.url_list?.[0] || '',
    follower_count: firstCount(rawUser.followerCount, rawUser.follower_count, rawUser.followersCount, rawUser.followers_count, stats.followerCount, stats.follower_count, stats.followersCount, stats.followers_count),
    following_count: firstCount(rawUser.followingCount, rawUser.following_count, rawUser.followingsCount, rawUser.followings_count, stats.followingCount, stats.following_count, stats.followingsCount, stats.followings_count)
  };
}

function hasTikTokStats(user) {
  return Number.isFinite(user?.follower_count) && Number.isFinite(user?.following_count);
}

function mergeTikTokUsers(primary, secondary, username) {
  if (!secondary || secondary.unique_id?.toLowerCase() !== username.toLowerCase()) return primary;
  if (!primary) return secondary;
  return {
    ...primary,
    nickname: primary.nickname || secondary.nickname,
    avatar: primary.avatar || secondary.avatar,
    follower_count: primary.follower_count ?? secondary.follower_count,
    following_count: primary.following_count ?? secondary.following_count
  };
}

function findProfileInData(value, username, visited = new Set()) {
  if (!value || typeof value !== 'object' || visited.has(value)) return null;
  visited.add(value);
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = findProfileInData(item, username, visited);
      if (found) return found;
    }
    return null;
  }

  const possibleUser = value.user || value.userInfo?.user;
  const possibleStats = value.stats || value.userInfo?.stats;
  const normalised = normaliseTikTokUser(possibleUser, possibleStats);
  if (normalised && normalised.unique_id.toLowerCase() === username.toLowerCase()) return normalised;

  for (const child of Object.values(value)) {
    const found = findProfileInData(child, username, visited);
    if (found) return found;
  }
  return null;
}

async function fetchTikTokProfile(username) {
  const profileResponse = await axios.get(`https://www.tiktok.com/@${encodeURIComponent(username)}`, {
    headers: browserHeaders,
    timeout: 10000,
    maxRedirects: 3
  });

  const html = profileResponse.data;
  const universalData = readJsonScript(html, '__UNIVERSAL_DATA_FOR_REHYDRATION__');
  const sigiState = readJsonScript(html, 'SIGI_STATE');
  const universalUserInfo = universalData?.__DEFAULT_SCOPE__?.['webapp.user-detail']?.userInfo;
  const user =
    universalUserInfo?.user ||
    sigiState?.UserModule?.users?.[username] ||
    Object.values(sigiState?.UserModule?.users || {})[0];
  const stats = universalUserInfo?.stats || sigiState?.UserModule?.stats?.[username] || {};

  let parsedProfile = normaliseTikTokUser(user, stats) || findProfileInData(universalData, username) || findProfileInData(sigiState, username);
  let followerCount = parsedProfile?.follower_count;
  let followingCount = parsedProfile?.following_count;

  if (followerCount === undefined || followingCount === undefined) {
    const desc = readMeta(html, 'og:description') || readMeta(html, 'description');
    if (desc) {
      const followerMatch = desc.match(/([\d.,]+[KMB]?)\s*Followers/i);
      const followingMatch = desc.match(/([\d.,]+[KMB]?)\s*Following/i);
      if (followerMatch) followerCount = parseCountFromText(followerMatch[1]);
      if (followingMatch) followingCount = parseCountFromText(followingMatch[1]);
    }
  }

  if (!parsedProfile) {
    const title = readMeta(html, 'og:title');
    const titleMatch = title.match(/^(.*?)\s*\(@([^)]*)\)/);
    if (!titleMatch) return null;
    return {
      unique_id: titleMatch[2],
      nickname: titleMatch[1].trim() || titleMatch[2],
      avatar: readMeta(html, 'og:image'),
      follower_count: followerCount,
      following_count: followingCount
    };
  }

  return {
    ...parsedProfile,
    follower_count: followerCount,
    following_count: followingCount
  };
}

async function fetchTikTokOEmbed(username) {
  const profileUrl = `https://www.tiktok.com/@${username}`;
  const response = await axios.get('https://www.tiktok.com/oembed', {
    params: { url: profileUrl },
    headers: browserHeaders,
    timeout: 10000
  });

  if (!response.data?.author_name || !response.data?.author_url) return null;
  const returnedHandle = response.data.author_url.match(/@([^/?]+)/)?.[1];
  if (!returnedHandle || returnedHandle.toLowerCase() !== username.toLowerCase()) return null;

  return {
    unique_id: returnedHandle,
    nickname: response.data.author_name,
    avatar: response.data.thumbnail_url || '',
    official_embed: true
  };
}

// TikTok blocks unauthenticated server-side profile scraping frequently. A
// TikAPI key provides a stable, authorized source for public profile stats.
async function fetchTikApiProfile(username) {
  if (!process.env.TIKAPI_KEY || process.env.TIKAPI_KEY === 'YOUR_REAL_TIKAPI_KEY') return null;
  const response = await axios.get('https://api.tikapi.io/public/check', {
    params: { username },
    headers: { 'X-API-KEY': process.env.TIKAPI_KEY },
    timeout: 10000
  });
  return findProfileInData(response.data, username);
}

// TikTok user info proxy. Official public profile data is tried first.
app.get('/api/tiktok-user', requireAuth, async (req, res) => {
  const username = req.query.username;
  if (!username) {
    return res.status(400).json({ error: 'Username query parameter is required' });
  }

  try {
    const cleanHandle = username.replace(/^@+/, '').trim();
    if (!/^[A-Za-z0-9._]{2,24}$/.test(cleanHandle)) {
      return res.status(400).json({ error: 'Enter a valid TikTok username' });
    }
    let user = null;
    const cached = profileCache.get(cleanHandle.toLowerCase());
    if (cached && Date.now() - cached.createdAt < PROFILE_CACHE_TTL_MS) {
      return res.json({ code: 0, data: { user: cached.user } });
    }
    const unavailableAt = unavailableProfileCache.get(cleanHandle.toLowerCase());
    if (unavailableAt && Date.now() - unavailableAt < UNAVAILABLE_PROFILE_CACHE_TTL_MS) {
      return res.json({ code: 0, data: { user: fallbackTikTokProfile(cleanHandle) } });
    }

    try {
      user = await fetchTikApiProfile(cleanHandle);
    } catch (tikApiError) {
      logLookupFailure('TikAPI profile lookup failed', tikApiError);
    }

    if (!hasTikTokStats(user)) {
      try {
        const scrapedUser = await fetchTikTokProfile(cleanHandle);
        user = mergeTikTokUsers(user, scrapedUser, cleanHandle);
      } catch (officialError) {
        logLookupFailure('Official TikTok profile lookup failed', officialError);
      }
    }

    if (!user) {
      try {
        user = await fetchTikTokOEmbed(cleanHandle);
      } catch (oEmbedError) {
        logLookupFailure('Official TikTok oEmbed lookup failed', oEmbedError);
      }
    }

    // oEmbed supplies identity and an avatar only. Always continue to the
    // stats provider until both public counts have been obtained.
    if (!hasTikTokStats(user)) {
      try {
        const fallback = await axios.get(`https://www.tikwm.com/api/user/info?unique_id=${cleanHandle}`, {
          headers: browserHeaders,
          timeout: 8000
        });
        const fallbackData = fallback.data?.code === 0 ? fallback.data?.data : null;
        const fallbackUser = normaliseTikTokUser(fallbackData?.user, fallbackData?.stats);
        user = mergeTikTokUsers(user, fallbackUser, cleanHandle);
      } catch (fallbackError) {
        logLookupFailure('Fallback TikTok profile lookup failed', fallbackError);
      }
    }

    if (user) {
      user = normaliseTikTokUser(user) || user;
      profileCache.set(cleanHandle.toLowerCase(), { user, createdAt: Date.now() });
      res.set('Cache-Control', 'public, max-age=60');
      return res.json({ code: 0, data: { user } });
    }

    unavailableProfileCache.set(cleanHandle.toLowerCase(), Date.now());
    return res.json({ code: 0, data: { user: fallbackTikTokProfile(cleanHandle) } });
  } catch (error) {
    logLookupFailure('Error fetching TikTok user', error);
    const cleanHandle = String(req.query.username || '').replace(/^@+/, '').trim();
    return res.json({ code: 0, data: { user: fallbackTikTokProfile(cleanHandle) } });
  }
});

app.use((req, res, next) => req.path === '/users.json' ? res.status(404).end() : next());
app.use(express.static(__dirname));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
}

module.exports = app;
