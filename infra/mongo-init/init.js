db = db.getSiblingDB(process.env.MONGO_INITDB_DATABASE || "api_protection");

db.security_logs.createIndex({ timestamp: -1 });
db.security_logs.createIndex({ request_id: 1 }, { unique: false });
db.security_logs.createIndex({ decision: 1, timestamp: -1 });

db.api_keys.createIndex({ key_hash: 1 }, { unique: true });
db.api_keys.createIndex({ status: 1 });

db.policies.createIndex({ path: 1, method: 1 }, { unique: true });

db.api_keys.updateOne(
  { _id: "seed-test-key" },
  {
    $set: {
      key_hash: "4c806362b613f7496abf284146efd31da90e4b16169fe001841ca17290f427c4",
      name: "seed_test_key",
      status: "active",
      owner_id: "1001",
      created_at: new Date(),
      expires_at: new Date("2099-01-01T00:00:00Z")
    }
  },
  { upsert: true }
);

db.policies.updateOne(
  { _id: "policy-admin-delete-users" },
  {
    $set: {
      path: "/api/v1/users/*",
      method: "DELETE",
      role: "admin",
      created_at: new Date()
    }
  },
  { upsert: true }
);
