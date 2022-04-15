// WALLET is the KV namespace we need to have

/**
 * Data structure:
 *  - wallet_<walletid>:
 *      - id: <walletid>
 *      - name
 *      - description
 *      - access: list of users who have access to it
 *          - id
 *          - name
 *      - extra: anything that can be turned into JSON
 *      - balance
 *      - created_by
 *        - id
 *        - name
 *      - created_at
 *  - transaction_<walletid>_<transactionid>:
 *      - id
 *      - title
 *      - amount
 *      - wallet_id
 *      - created_by
 *        - id
 *        - name
 *      - extra: anything that can be turned into JSON
 *      - created_at
 *  - user_<userid>
 *      - id
 *      - name
 *      - wallets: list of wallets
 *         - id
 *         - name
 *  - auth_<name>
 *      - id
 *      - password
 */

const SALT = "SALT_NEEDS_CHANGE";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods":
    "GET, HEAD, POST, OPTIONS, PUT, DELETE, PATCH",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

/**
 * Generate unique ids
 * @returns {string}
 */
const genId = () => btoa(`${Math.random()}`.substr(2)).replace(/=/g, "");
/**
 * Grab current time in ISO string format
 * @returns {string}
 */
const now = () => new Date().toISOString();
/**
 * Write data into KV
 * @param key
 * @param data
 * @returns {*}
 */
const write = (key, data) => WALLET.put(key, JSON.stringify(data));
/**
 * Read data from KV
 * @param key
 * @returns {Promise<*>}
 */
const read = async (key) => {
  const data = await WALLET.get(key, { type: "json" });
  if (data !== null) {
    return data;
  }
  throw new Error("404");
};
/**
 * Protect the endpoint
 * @param me
 */
const protect = (me) => {
  if (!me) {
    throw new Error("Authentication required");
  }
};

/**
 * Grab a wallet from KV
 * @param me
 * @param walletId
 * @returns {Promise<(string|*)[]>}
 */
const grabProtectedWalletByUserId = async (me, walletId) => {
  protect(me);
  const key = `wallet_${walletId}`;
  const item = await read(key);
  if (!item.access.map((e) => e.id).includes(me.id)) {
    throw new Error("Cannot access this wallet!");
  }
  return [key, item];
};

const grabProtectedWallet = async (walletId) => {
  //protect(me);
  const key = `wallet_${walletId}`;
  const item = await read(key);
  if (!item.access.map((e) => e.id)) {
    throw new Error("Cannot access this wallet!");
  }
  return [key, item];
};
/**
 * Calculate a simple hash for passwords
 * @param pass
 * @returns {Promise<string>}
 */
const encodePass = async (pass) => {
  const x = new Uint8Array(
    await crypto.subtle.digest(
      {
        name: "SHA-256",
      },
      new TextEncoder().encode(`${SALT}_${pass}`)
    )
  );
  return x.join("");
};

/**
 * Login endpoint, which generates a session token on success
 * @param me
 * @param data
 * @returns {Promise<{user: *, token: string}>}
 */
async function login(me, data) {
  if (me) {
    throw new Error("Already logged in!");
  }
  let login = null;
  try {
    login = await read(`auth_${`${data.name}`.toLowerCase().trim()}`);
  } catch (err) {
    throw new Error("Cannot find this user!");
  }
  if (login.password !== (await encodePass(data.password))) {
    throw new Error("Wrong password!");
  }
  const user = await read(`user_${login.id}`);
  const token = `${login.id}_${genId()}`;

  return {
    token: `${token}_${await encodePass(`${token}`)}`,
    user,
  };
}

/**
 * Registration endpoint
 * @param me
 * @param data
 * @returns {Promise<{name: string, wallets: *[], id: string}>}
 */
async function reg(me, data) {
  const NAME_REGEX = /^[0-9a-zA-Z]*$/g;
  if (me) {
    throw new Error("Already logged in!");
  }
  if (NAME_REGEX.test(`${data.name}`) === false) {
    throw new Error(
      "Name can only include numbers, upper and lowercase characters!"
    );
  }
  if (`${data.password}`.length === 0) {
    throw new Error("Password cannot be empty!");
  }
  const name = `${data.name}`.toLowerCase().trim();
  const hasAlready = await read(`auth_${name}`).catch((err) => false);
  if (hasAlready !== false) {
    throw new Error("Name is already in use!");
  }
  const newUser = {
    id: genId(),
    name: `${data.name}`,
    admin: data.admin,
    wallets: [],
  };
  const newAuth = {
    id: newUser.id,
    password: await encodePass(`${data.password}`),
  };
  await write(`auth_${name}`, newAuth);
  await write(`user_${newUser.id}`, newUser);
  return newUser;
}

/**
 * Grab user data using id
 * @param me
 * @param data
 * @returns {Promise<*>}
 */
async function getUserById(me, data) {
  const user = await read(`user_${data.id}`);
  delete user.wallets;
  return user;
}

/**
 * Grab id from username
 * @param me
 * @param data
 * @returns {Promise<*>}
 */
async function getIdByName(me, data) {
  const NAME_REGEX = /^[0-9a-zA-Z]*$/g;
  protect(me);
  if (NAME_REGEX.test(`${data.name}`) === false) {
    throw new Error(
      "Name can only include numbers, upper and lowercase characters!"
    );
  }
  const name = `${data.name}`.toLowerCase().trim();
  const auth_user = await read(`auth_${name}`);
  return auth_user.id;
}

/**
 * Create a new wallet
 * @param me
 * @param data
 * @returns {Promise<{access: [{name, id}], balance: number, extra: (*|{}), name: (string), description: (string), created_at: string, id: string, created_by: {name, id}}>}
 */
async function createWallet(me, data) {
  protect(me);
  const id = genId();
  const item = {
    id: id,
    name: `${data.name}` || "",
    description: `${data.description}` || "",
    closed: 0,
    // instant access to the creator
    access: [
      {
        id: me.id,
        name: me.name,
      },
    ],
    extra: data.extra || {},
    balance: 0,
    created_by: {
      id: me.id,
      name: me.name,
    },
    created_at: now(),
  };
  me.wallets.push({
    id: item.id,
    name: item.name,
  });
  await write(`wallet_${item.id}`, item);
  await write(`user_${me.id}`, me);
  return item;
}

/**
 * Update description + extra in a wallet
 * @param me
 * @param data
 * @returns {Promise<*>}
 */
async function closeWallet(data) {
  
  const [walletKey, item] = await grabProtectedWallet(data.id);
  /*if (typeof data.description !== "undefined") {
    item.description = `${data.description}`;
  }
  if (typeof data.extra !== "undefined") {
    item.extra = data.extra;
  }
  if (typeof data.closed !== "undefined") {
    item.closed = data.closed;
  }*/
  item.isLocked = 1;
  await write(walletKey, item);
  return item;
}

/**
 * Grab wallet data
 * @param me
 * @param data
 * @returns {Promise<*>}
 */
async function getWallet(data) {
  
  const [_walletKey, item] = await grabProtectedWallet(data.id);
  return item;
}

async function getWalletByUid(me, data) {
  const [_walletKey, item] = await grabProtectedWalletByUserId(me,data.id);
  return item;
}

async function getWallets(me, data) {
  protect(me);
  const user = await read(`user_${me.id}`);
  return user.wallets;
}

async function getAllWallets() {
  const allWallets = await WALLET.list({
    prefix: 'wallet_'
  });
  const wallets = [];
  for (const wallet of allWallets.keys) {
    wallets.push(JSON.parse(await WALLET.get(wallet.name)))
  }
  return wallets;
}

async function getAllTransactions() {
  const allTransactions = await WALLET.list({
    prefix: 'transaction_'
  });

  const transactions = [];
  for (const transaction of allTransactions.keys) {
    transactions.push(JSON.parse(await WALLET.get(transaction.name)))
  }

  return transactions;
}

/**
 * Delete a wallet
 * @param me
 * @param data
 * @returns {Promise<*>}
 */
async function deleteWallet(me, data) {
  const [walletKey, item] = await grabProtectedWalletByUserId(data.id);

  // fix up wallets in the users' list
  for (let i = 0; i < item.access.length; i++) {
    try {
      const oneUser = await read(`user_${item.access[i].id}`);
      oneUser.wallets = oneUser.wallets.filter((e) => e.id !== data.id);
      await write(`user_${item.access[i].id}`, oneUser);
    } catch (err) {
      // we could not patch a user
      console.log(err);
    }
  }

  // remove wallet from the system
  // TODO: we can care about the transactions
  await WALLET.delete(walletKey);
  return item;
}

/**
 * Invite a user to a wallet
 * @param me
 * @param data
 * @returns {Promise<string|*>}
 */
async function addAccessToWallet(me, data) {
  const [walletKey, item] = await grabProtectedWallet(data.wallet_id);
  if (item.access.map((e) => e.id).includes(`${data.user_id}`)) {
    throw new Error("Access is already granted to that user!");
  }
  const otherUserKey = `user_${data.user_id}`;
  let otherUser = await read(otherUserKey).catch((err) => false);
  if (otherUser === false) {
    throw new Error("Cannot find user!");
  }

  otherUser.wallets.push({ id: item.id, name: item.name });
  item.access.push({ id: otherUser.id, name: otherUser.name });

  await write(otherUserKey, otherUser);
  await write(walletKey, item);
  return item;
}

/**
 * Remove access from a user to a wallet
 * @param me
 * @param data
 * @returns {Promise<string|*>}
 */
async function removeAccessFromWallet(me, data) {
  const [walletKey, item] = await grabProtectedWallet(data.wallet_id);
  if (!item.access.map((e) => e.id).includes(`${data.user_id}`)) {
    throw new Error("User has no access to the wallet!");
  }
  if (item.access.length <= 1) {
    throw new Error("Cannot remove last user from a wallet!");
  }

  const otherUserKey = `user_${data.user_id}`;
  const otherUser = await read(otherUserKey);

  otherUser.wallets = otherUser.wallets.filter((e) => e.id !== item.id);
  item.access = item.access.filter((e) => e.id !== otherUser.id);

  await write(otherUserKey, otherUser);
  await write(walletKey, item);
  return item;
}

/**
 * Grab wallet data
 * @param me
 * @param data
 * @returns {Promise<string|*>}
 */
/*
async function getWallet(me, data) {
  const [_walletKey, item] = await grabProtectedWallet(me, data.id);
  return item;
}
*/
/**
 * List transactions for a specific wallet
 * @param me
 * @param data
 * @returns {Promise<{cursor, has_more: boolean, transactions: *[]}>}
 */
async function listTransactions(me, data) {
  // just to make sure we have access
  const [_walletKey, wallet] = await grabProtectedWallet(data.wallet_id);

  let limit = parseInt(data.limit || "5", 10);
  if (Number.isNaN(limit)) {
    limit = 5;
  }
  const alltransactions = await WALLET.list({
    prefix: `transaction_${wallet.id}_`,
    limit,
    cursor: data.cursor,
  });

  const ids = alltransactions.keys.map((e) => e.name);
  const transactions = [];
  for (let i = 0; i < ids.length; i++) {
    // ids are prefixed with suggestion_
    try {
      transactions.push(await read(ids[i]));
    } catch (err) {
      // silently crying in the corner
    }
  }
  return {
    transactions,
    has_more: !alltransactions.list_complete,
    cursor: alltransactions.cursor,
  };
}

async function listTransactionsByUserId(me) {
  protect(me);
  // just to make sure we have access

  /*const alltransactions = await WALLET.list({
    prefix: `transaction_${wallet.id}_`,
  });*/

  const alltransactions = await getAllTransactions();
  //const ids = alltransactions.keys.map((e) => e.created_by.id = me.id);
  const transactions = [];
  for (let i = 0; i < alltransactions.length; i++) {
    // ids are prefixed with suggestion_
    if(alltransactions[i].created_by.id == me.id){
      transactions.push(alltransactions[i]);
    }
  }

  return {
    transactions,
    has_more: !alltransactions.list_complete,
    cursor: alltransactions.cursor,
  };
}

/**
 * List users with a specific prefix
 * @param me
 * @param data
 * @returns {Promise<{cursor, has_more: boolean, users: *[]}>}
 */
async function listUsers(me, data) {
  protect(me);

  let limit = parseInt(data.limit || "5", 10);
  if (Number.isNaN(limit)) {
    limit = 5;
  }

  // grab users with a prefix
  const allusers = await WALLET.list({
    prefix: `auth_${data.prefix || ""}`,
    limit,
    cursor: data.cursor,
  });

  const kvKeys = allusers.keys.map((e) => e.name);
  const users = [];
  for (let i = 0; i < kvKeys.length; i++) {
    // ids are prefixed with suggestion_
    try {
      const authData = await read(kvKeys[i]);
      const userData = await read(`user_${authData.id}`);
      users.push({
        id: userData.id,
        name: userData.name,
      });
    } catch (err) {
      // silently crying in the corner
    }
  }
  return {
    users,
    has_more: !allusers.list_complete,
    cursor: allusers.cursor,
  };
}

async function createTransaction(me, data) {
  //{ ...data, wallet_id: id }, { ...data, amount: amount }
  const [walletKey, wallet] = await grabProtectedWallet(data.wallet_id);

  let amount = parseFloat(`${data.amount}`);
  if (Number.isNaN(amount)) {
    amount = 0;
  }

  const item = {
    id: `${wallet.id}_${genId()}`,
    amount,
    name: wallet.name,
    extra: data.extra || {},
    wallet_id: wallet.id,
    created_by: {
      id: me.id,
      name: me.name,
    },
    created_at: now(),
  };
  wallet.balance += item.amount;
  await write(`transaction_${item.id}`, item);
  await write(walletKey, wallet);
  return item;
}

/**
 * Get transaction (checks the wallet as well)
 * @param me
 * @param data
 * @returns {Promise<*>}
 */
async function getTransaction(me, data) {
  const item = await read(`transaction_${data.id}`);
  await grabProtectedWalletByUserId(me, item.wallet_id);
  return item;
}

/**
 * Update transaction (modifies the wallet as well)
 * @param me
 * @param data
 * @returns {Promise<*>}
 */
async function updateTransaction(me, data) {
  const item = await read(`transaction_${data.id}`);
  const [walletKey, wallet] = await grabProtectedWalletByUserId(me, item.wallet_id);

  if (typeof data.name !== "undefined") {
    item.name = `${data.name}`;
  }
  if (typeof data.extra !== "undefined") {
    item.extra = data.extra;
  }
  // changing amount is tricky
  if (typeof data.amount !== "undefined") {
    const oldAmount = item.amount;
    let newAmount = parseFloat(`${data.amount}`);
    if (Number.isNaN(newAmount)) {
      newAmount = 0;
    }
    if (newAmount !== oldAmount) {
      wallet.balance += newAmount - oldAmount;
      await write(walletKey, wallet);
      item.amount = newAmount;
    }
  }
  await write(`transaction_${item.id}`, item);
  return item;
}

/**
 * Delete transaction (modifies the wallet as well)
 * @param me
 * @param data
 * @returns {Promise<*>}
 */
async function deleteTransaction(me, data) {
  const itemKey = `transaction_${data.id}`;
  const item = await read(itemKey);
  // to check the access
  const [walletKey, wallet] = await grabProtectedWalletByUserId(me, item.wallet_id);

  wallet.balance -= item.amount;
  await write(walletKey, wallet);
  await WALLET.delete(itemKey);
  return item;
}

/**
 * Resolve auth token to an actual user
 * @param token
 * @returns {Promise<*>}
 */
async function resolveAuthorization(token) {
  const [userid, random, hash] = token.split("_", 3);
  if (hash !== (await encodePass(`${userid}_${random}`))) {
    throw new Error("Authentication required");
  }
  return await read(`user_${userid}`);
}

const ROUTE_MAP = [
  ["POST", /^login$/, login],
  ["POST", /^reg$/, reg],
  [
    "GET",
    /^user\/(.*)$/,
    (id) => {
      return (me, data) => getUserById(me, { ...data, id: id });
    },
  ],
  ["GET", /^wallets$/, getWallets],
  ["GET", /^allwallets$/, getAllWallets],
  ["POST", /^user\/search$/, getIdByName],
  ["POST", /^user\/list$/, listUsers],
  ["PUT", /^wallet$/, createWallet],
  [
    "GET",
    /^walletbyUid\/(.*)$/,
    (id) => {
      return (me, data) => getWalletByUid(me, { ...data, id: id });
    },
  ],
  [
    "GET",
    /^wallet\/(.*)$/,
    (id) => {
      return (data) => getWallet({ ...data, id: id });
    },
  ],
  [
    "POST",
    /^closewallet\/(.*)$/,
    (id) => {
      return (data) => closeWallet({ ...data, id: id });
    },
  ],
  [
    "DELETE",
    /^walletbyUid\/(.*)$/,
    (id) => {
      return (me, data) => deleteWallet(me, { ...data, id: id });
    },
  ],
  [
    "POST",
    /^wallet\/(.*)\/grant_access$/,
    (id) => {
      return (me, data) => addAccessToWallet(me, { ...data, wallet_id: id });
    },
  ],
  [
    "POST",
    /^wallet\/(.*)\/remove_access$/,
    (id) => {
      return (me, data) =>
        removeAccessFromWallet(me, { ...data, wallet_id: id });
    },
  ],
  ["POST", /^transactions\/(.*)$/, 
    (id) => {
      return (me, data) => listTransactions(me, { ...data, wallet_id: id });
    }, 
  ],
  ["GET", /^transactionsbyuid$/,listTransactionsByUserId],
  
  ["PUT", /^transaction\/(.*)$/,
    (id) => {
      return (me, data) => createTransaction(me, { ...data, wallet_id: id });
    }, 
  ],
  [
    "GET",
    /^transaction\/(.*)$/,
    (id) => {
      return (me, data) => getTransaction(me, { ...data, id });
    },
  ],
  [
    "PATCH",
    /^transaction\/(.*)$/,
    (id) => {
      return (me, data) => updateTransaction(me, { ...data, id });
    },
  ],
  [
    "DELETE",
    /^transaction\/(.*)$/,
    (id) => {
      return (me, data) => deleteTransaction(me, { ...data, id });
    },
  ],
];

async function router(method, uri, me, data) {
  const endpointCandidate = ROUTE_MAP.find((route) => {
    if (route[0] !== method) {
      return false;
    }
    if (!route[1].test(uri)) {
      return false;
    }
    return true;
  });
  if (!endpointCandidate) {
    throw new Error("No route");
  }

  let params = [...uri.match(endpointCandidate[1])];
  params.shift();
  if (params.length === 0) {
    return await endpointCandidate[2](me, data);
  }
  return await endpointCandidate[2](...params)(me, data);
}

addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(req) {
  const url = new URL(req.url).pathname.substr(1);
  let result = {};
  let status = 200;

  if (req.method === "OPTIONS") {
    return new Response("", {
      status,
      headers: {
        ...corsHeaders,
        "content-type": "application/json;charset=UTF-8",
      },
    });
  }

  try {
    const postData = (req.headers.get("content-type") || "").includes(
      "application/json"
    )
      ? await req.json()
      : {};
    let me = false;
    const authHeader = req.headers.get("authorization");
    if (authHeader && authHeader.indexOf("Bearer ") === 0) {
      me = await resolveAuthorization(authHeader.substr(7));
    }
    result = await router(req.method, url, me, postData);
  } catch (err) {
    status = 400;
    switch (err.toString()) {
      case "Error: 404":
        status = 404;
        break;
      case "Error: Authentication required":
        status = 403;
        break;
    }
    result = {
      error: err.toString(),
    };
  }

  return new Response(JSON.stringify(result, null, 2), {
    status,
    headers: {
      ...corsHeaders,
      "content-type": "application/json;charset=UTF-8",
    },
  });
}
