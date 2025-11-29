const DB_NAME = 'secure-e2ee-chat';
const DB_VERSION = 1;
const STORE_NAME = 'keys';

const openDatabase = () => {
  return new Promise((resolve, reject) => {
    const request = window.indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'username' });
      }
    };

    request.onsuccess = () => {
      resolve(request.result);
    };

    request.onerror = () => {
      reject(request.error);
    };
  });
};

export const storePrivateKey = async (username, encryptedBundle) => {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    store.put({ username, encrypted: encryptedBundle });

    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
};

export const retrievePrivateKey = async (username) => {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
    const request = store.get(username);

    request.onsuccess = () => {
      if (request.result) {
        resolve(request.result.encrypted);
      } else {
        resolve(null);
      }
    };

    request.onerror = () => reject(request.error);
  });
};


