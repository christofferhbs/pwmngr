function add(masterPassword, entryName, username, password) {
    
}

function get(masterPassword, entryName) {

}


const command = process.argv[2];

if (command === "add") {
    const masterPassword = process.argv[3];
    const entryName = process.argv[4];
    const username = process.argv[5];
    const password = process.argv[6];

    add(masterPassword, entryName, username, password);
}

if (command === "get") {
    const masterPassword = process.argv[3];
    const entryName = process.argv[4];

    get(masterPassword, entryName);
}