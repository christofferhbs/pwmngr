function create(masterPassword) {}

function openVault(masterPassword) {}

function saveVault(entries, key, salt) {}

function add(masterPassword, name, username, password) {}

function get(masterPassword, name) {}

const command = process.argv[2];

if (command === "create") {
  const masterPassword = process.argv[3];

  create(masterPassword);
}

if (command === "add") {
  const masterPassword = process.argv[3];
  const name = process.argv[4];
  const username = process.argv[5];
  const password = process.argv[6];

  add(masterPassword, name, username, password);
}

if (command === "get") {
  const masterPassword = process.argv[3];
  const name = process.argv[4];

  get(masterPassword, name);
}
