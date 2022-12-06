const mysql = require('mysql2');

const db = mysql.createConnection({
    host: 'node418489-onlineshopping.j.layershift.co.uk',
    user: 'root',
    password: 'BPHpoy47384',
    database: 'carshop'
});

module.exports = db;