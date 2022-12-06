const express = require("express");
const bodyParser = require("body-parser");
const con = require("./database.js");
const bcrypt = require('bcrypt');
const session = require("express-session");
const passport = require("passport");
const mongoose = require("mongoose");
const passportLocalMongoose = require("passport-local-mongoose");
const saltRounds = 10;
const _ = require("lodash");
const { result } = require("lodash");


const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs')
app.use(express.static("public"));


app.use(session({
    secret: "we are friends",
    resave: false,
    saveUninitialized: false,
})
);



app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb+srv://anasbaqai:An12as34@cluster0.uuocn2n.mongodb.net/carshopDB");
// mongoose.connect("mongodb://localhost:27017/carshopDB");

const usersSchema = new mongoose.Schema({
    username: String,
    password: String,
});
usersSchema.plugin(passportLocalMongoose);
const User = mongoose.model("User", usersSchema)
passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

function convert(str) {
    var date = new Date(str),
        mnth = ("0" + (date.getMonth() + 1)).slice(-2),
        day = ("0" + date.getDate()).slice(-2);
    return [date.getFullYear(), mnth, day].join("-");
}

/******************************************ROUTES ******************************** */



/************************************** create admin route **************************/
app.get("/createAdmin", (req, res) => {
    res.sendFile(__dirname + "/views/adminCreate.html")
})




app.post("/createAdmin", (req, res) => {


    bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
        // Store hash in your password DB.
        User.register({ username: req.body.username }, req.body.password, function (err, user) {
            if (err) {
                console.log(err);

            } else {
                passport.authenticate("local")(req, res, function () {

                })
            }
        })
        var admin = {
            branch: req.body.branch,
            username: req.body.username,
            hashPass: hash,
        }

        const sql = "insert into admins set ?";
        con.query(sql, admin, (err, results) => {
            if (err) {
                console.log(err);
            } else {
                res.redirect("/");

            }
        })
    })



})


/********************************* login route **************************************/

app.get("/", function (req, res) {
    res.render("login");


})
/*** sign up route ******/


app.post("/signup", (req, res) => {
    bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
        // Store hash in your password DB.


        var user = {
            name: req.body.name,
            cnic: req.body.cnic,
            phone: req.body.phone,
            email: req.body.username,
            hashPass: hash,
        }

        const sql = "insert into users set ?";
        con.query(sql, user, (err, results) => {
            if (err) {
                res.render("failure", { fail: err })
            } else {

                res.render("failure", { fail: "you are sign up successfully" })

            }
        })
    })
})




app.post("/", (req, res) => {

    var username = req.body.username;

    const user = new User({
        username: req.body.username,
        password: req.body.password,
    })
    req.login(user, function (err) {
        if (err) {
            res.render("failure", { fail: err })
        } else {
            if (username.indexOf("admin") > -1) {

                const sql = "select * from admins where username=?";
                con.query(sql, username, (err, results) => {
                    if (err) {
                        console.log(err);
                        res.redirect("/");
                    } else {

                        if (results.length === 0) {
                            res.render("failure", { fail: "username is incorrect" })
                        } else {
                            bcrypt.compare(req.body.password, results[0].hashPass, function (err, result) {
                                if (result === true) {
                                    passport.authenticate("local")(req, res, function () {
                                        res.redirect("/home");
                                    })
                                    // res.redirect("/home")
                                } else {
                                    res.render("failure", { fail: "password is incorrect" })
                                }
                            });
                        }

                    }
                })
            } else {
                const sql = "select * from users where email=?";
                con.query(sql, username, (err, results) => {
                    if (err) {
                        console.log(err);
                        res.redirect("/");
                    } else {
                        console.log(results);
                        if (results.length === 0) {
                            res.render("failure", { fail: "username is incorrect" })
                        } else {
                            bcrypt.compare(req.body.password, results[0].hashPass, function (err, result) {
                                if (result === true) {
                                    res.redirect("/userHome/" + username);
                                } else {
                                    res.render("failure", { fail: "password is incorrect" })
                                }
                            });
                        }

                    }
                })
            }
        }
    })


})

/*********************************** update pass route *********************/
app.get("/update", (req, res) => {
    res.render("updatePass");

})


app.post("/update", (req, res) => {
    var username = req.body.email;
    if (username.indexOf("admin") > -1) {
        const sql = "select * from admins where username=?";
        con.query(sql, req.body.email, (err, results) => {
            if (err) {
                res.render("failure", { fail: err })
            }
            if (results.length === 0) {
                res.render("failure", { fail: "username is incorrect" })
            } else {
                bcrypt.compare(req.body.oldpassword, results[0].hashPass, function (err, result) {
                    if (err) {
                        res.render("failure", { fail: err })
                    }
                    if (result === true) {
                        bcrypt.hash(req.body.newpassword, saltRounds, function (err, hash) {
                            if (err) {
                                res.render("failure", { fail: err })
                            }
                            const sql = "update admins set hashPass=? where username=?";
                            con.query(sql, [hash, req.body.email], (err, results) => {
                                if (err) {
                                    res.render("failure", { fail: err })
                                }
                                res.render("failure", { fail: "pass changed successfully" })

                            })
                        })

                    } else {
                        res.render("failure", { fail: "incorrect old password" });
                    }
                });
            }

        })


    } else {
        const sql = "select * from users where email=?";
        con.query(sql, req.body.email, (err, results) => {
            if (err) {
                res.render("failure", { fail: err })
            }
            if (results.length === 0) {
                res.render("failure", { fail: "username is incorrect" })
            } else {
                bcrypt.compare(req.body.oldpassword, results[0].hashPass, function (err, result) {
                    if (err) {
                        res.render("failure", { fail: err })
                    }
                    if (result === true) {
                        bcrypt.hash(req.body.newpassword, saltRounds, function (err, hash) {
                            if (err) {
                                res.render("failure", { fail: err })
                            }
                            const sql = "update users set hashPass=? where email=?";
                            con.query(sql, [hash, req.body.email], (err, results) => {
                                if (err) {
                                    res.render("failure", { fail: err })
                                }
                                res.render("failure", { fail: "password change successfully" })

                            })
                        })

                    } else {
                        res.render("failure", { fail: "incorrect old password" })
                    }
                });
            }

        })
    }
})





/******************************** home route *************************************/



app.get("/home", (req, res) => {

    if (req.isAuthenticated()) {
        res.render("home", { cnic: "", plate: "" });
    } else {
        res.redirect("/");
    }



})

app.post("/plate", (req, res) => {
    plate = req.body.plate;
    let sql = "select cnic,plate from vehicle where plate=?";
    con.query(sql, plate, (err, result) => {
        if (err) {
            res.render("failure", { fail: err })
        } else {
            if (result.length === 0) {
                res.render("failure", { fail: "register the car first" })
            } else {
                res.render("home", { cnic: result[0].cnic, plate: result[0].plate });
            }
        }
    })
})



app.post("/register", (req, res) => {
    var service = {
        cnic: req.body.cnic,
        vehicle: req.body.plate,
        serviceDate: req.body.date,
        complain: req.body.complain,
        serviceProvided: req.body.service,
        total: req.body.total,
        branch: req.body.branch,
        customerName: req.body.customerName,
    }
    con.query("select * from admins where username=?", req.user.username, (err, result) => {
        if (err)
            res.render("failure", { fail: err })
        else {
            if (result[0].branch === 1 || result[0].branch === 2) {
                const sql = "insert into service set ?";
                con.query(sql, service, (err, results) => {
                    if (err) {

                        res.render("failure", { fail: err })
                    } else {
                        const sql = "call update_sale(?,?)";
                        con.query(sql, [convert(new Date().toISOString()), result[0].branch], (err, rs) => {
                            if (err) {
                                res.render("failure", { fail: err })
                            }

                            res.redirect("/home");
                        })

                    }
                })
            } else {
                res.render("failure", { fail: "superadmin cannot register service" })
            }
        }
    });

})


app.post("/register/vehicle", (req, res) => {
    var vehicle = {

        company: req.body.company,
        model: req.body.model,
        year: req.body.year,
        cnic: req.body.cnic,
        plate: req.body.plate,
        branch: req.body.branch,
    }

    const sql = "insert into vehicle set ?";
    con.query(sql, vehicle, (err, results) => {
        if (err) {

            res.render("failure", { fail: err })
        } else {

            res.redirect("/home");
        }
    })
})

/************************************ user page route *******************************/

app.get("/userHome/:username", (req, res) => {
    const email = req.params.username;
    let sql = "select cnic from users where email=?";
    con.query(sql, email, (err, result) => {
        let sql2 = "select * from vehicle v,users u where v.cnic=u.cnic and v.cnic=?";
        con.query(sql2, result[0].cnic, (err, results) => {
            if (results.length === 0) {
                res.render("failure", { fail: "please get your car registered from the store first" })
            }
            res.render("userHome", { vehicles: results });
        })
    })

})

/************************************** all service route ******************************/
app.get("/allServices", (req, res) => {

    if (req.isAuthenticated()) {
        con.query("select * from admins where username=?", req.user.username, (err, result) => {
            if (err)
                res.render("failure", { fail: err })
            else {
                if (result[0].branch === 1) {
                    let sql = "CREATE OR REPLACE VIEW service_branch_1 AS SELECT * from service where branch=?";
                    con.query(sql, result[0].branch, (err, results) => {
                        const sql = "select * from service_branch_1";
                        con.query(sql, (err, services) => {
                            res.render("allService", { services: services })
                        })

                    })
                } else if (result[0].branch === 2) {
                    let sql = "CREATE OR REPLACE VIEW service_branch_2 AS SELECT * from service where branch=?";
                    con.query(sql, result[0].branch, (err, results) => {
                        const sql = "select * from service_branch_2";
                        con.query(sql, (err, services) => {
                            res.render("allService", { services: services })
                        })

                    })
                } else {
                    let sql = "select * from service"
                    con.query(sql, (err, result) => {
                        res.render("allService", { services: result })
                    })
                }

            }
        })

    } else {
        res.redirect("/");
    }


})



app.get("/detail/service/:id", (req, res) => {
    let sql = "select * from service where id=?;"
    con.query(sql, req.params.id, (err, result) => {
        if (err) {
            res.render("failure", { fail: err })
        } else {

            res.render("specificService", { service: result });
        }
    })
})

/********************************** all vehicle route ********************************/
app.get("/allVehicles", (req, res) => {

    if (req.isAuthenticated()) {
        con.query("select * from admins where username=?", req.user.username, (err, result) => {
            if (err)
                res.render("failure", { fail: err })
            else {
                if (result[0].branch === 1) {
                    let sql = "CREATE OR REPLACE VIEW vehicles_branch_1 AS SELECT * from vehicle where branch=?";
                    con.query(sql, result[0].branch, (err, results) => {
                        const sql = "select * from vehicles_branch_1";
                        con.query(sql, (err, vehicle) => {
                            res.render("allVehicles", { vehicles: vehicle })
                        })

                    })
                } else if (result[0].branch === 2) {
                    let sql = "CREATE OR REPLACE VIEW vehicles_branch_2 AS SELECT * from vehicle where branch=?";
                    con.query(sql, result[0].branch, (err, results) => {
                        const sql = "select * from vehicles_branch_2";
                        con.query(sql, (err, vehicles) => {
                            res.render("allVehicles", { vehicles: vehicles })
                        })

                    })
                } else {
                    let sql = "select * from vehicle"
                    con.query(sql, (err, result) => {
                        res.render("allVehicles", { vehicles: result })
                    })
                }

            }
        })

    } else {
        res.redirect("/");
    }


})

app.get("/delete/vehicle/:plate", (req, res) => {
    let sql = "delete from vehicle where plate=?"
    con.query(sql, req.params.plate, (err, result) => {
        res.redirect("/allVehicles");
    })
})

/************************************** all users route ********************************/
app.get("/allUsers", (req, res) => {
    if (req.isAuthenticated()) {
        if (req.user.username === 'superadmin') {
            let sql = "select * from users";
            con.query(sql, (err, results) => {
                res.render("allUsers", { users: results })
            })
        } else {
            res.render("failure", { fail: "can only be accessed by superadmin" })
        }
    } else {
        res.redirect("/");
    }

})


/*********************** specific services realated to car route *************/
app.get("/specService/:plate", (req, res) => {
    let sql = "select s.* from service s where vehicle=? "
    con.query(sql, req.params.plate, (err, results) => {
        res.render("allService", { services: results })
    })

})

/************************** find specific car with plate **************/
app.get("/findVehicle", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("findVehicle");
    }

})

app.post("/findVehicle", (req, res) => {
    let sql = "select * from vehicle where plate=?";
    let plate = req.body.plate;
    con.query(sql, plate, (err, results) => {
        if (err) {
            res.render("failure", { fail: err })
        } else {

            if (results.length === 0) {

                res.render("failure", { fail: "this car is not registered" })
            } else {
                res.render("specVehicle", { vehicles: results });
            }
        }
    })

})

/*********************************** find specific user   *******************************/
app.get("/findUser", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("findUser");
    }
})

app.post("/findUser", (req, res) => {
    let sql = "select email from users where email=?";

    con.query(sql, req.body.email, (err, results) => {
        if (err) {
            res.render("failure", { fail: err })
        } else {

            if (results.length === 0) {

                res.render("failure", { fail: "user not found" })
            } else {
                res.redirect("/userHome/" + results[0].email);
            }
        }
    })

})

/************************************** employee registration route */

app.get("/register/employee", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("employeeRegistration")
    }
})

app.post("/register/employee", (req, res) => {
    let employee = {

        employee_name: req.body.employeeName,
        cnic: req.body.cnic,
        salary: req.body.salary,
        hire_date: req.body.date,
        branch: req.body.branch,
        address: req.body.address,
        phone: req.body.phone,
    }
    let sql = "insert into employees set ?";
    con.query(sql, employee, (err, result) => {
        if (err) {
            res.render("failure", { fail: err })
        } else {
            res.redirect("/register/employee");
        }
    })
})

/************************************** all employee page route ***********************/
app.get("/allEmployees", (req, res) => {
    if (req.isAuthenticated()) {
        con.query("select * from admins where username=?", req.user.username, (err, result) => {
            if (err)
                res.render("failure", { fail: err })
            else {
                if (result[0].branch === 1) {
                    let sql = "CREATE OR REPLACE VIEW employees_branch_1 AS SELECT * from employees where branch=?";
                    con.query(sql, result[0].branch, (err, results) => {
                        const sql = "select * from employees_branch_1";
                        con.query(sql, (err, employees) => {
                            if (employees.length === 0) {
                                res.render("failure", { fail: "no employee found" })
                            } else {
                                res.render("allEmployees", { employees: employees })
                            }
                        })

                    })
                } else if (result[0].branch === 2) {
                    let sql = "CREATE OR REPLACE VIEW employees_branch_2 AS SELECT * from employees where branch=?";
                    con.query(sql, result[0].branch, (err, results) => {
                        const sql = "select * from employees_branch_2";
                        con.query(sql, (err, employees) => {
                            if (employees.length === 0) {
                                res.render("failure", { fail: "no employeefound" })
                            } else {
                                res.render("allEmployees", { employees: employees })
                            }

                        })

                    })
                } else {
                    let sql = "select * from employees"
                    con.query(sql, (err, results) => {
                        if (err) {
                            res.render("failure", { fail: err })
                        } else {
                            if (results.length === 0) {
                                res.render("failure", { fail: "no employee found" })
                            } else {
                                res.render("allEmployees", { employees: results })
                            }
                        }
                    })
                }

            }
        })

    } else {
        res.redirect("/");
    }



})


app.get("/delete/employee/:id", (req, res) => {
    let sql = "delete from employees where employee_id=?";
    con.query(sql, req.params.id, (err, result) => {
        if (err) {
            res.render("failure", { fail: err })
        } else {
            res.redirect("/allEmployees");
        }
    })
})


/**************************************** employee attendance ************/


app.get("/attendance", (req, res) => {
    if (req.isAuthenticated()) {
        con.query("select * from admins where username=?", req.user.username, (err, result) => {
            if (err)
                res.render("failure", { fail: err })
            else {
                if (result[0].branch === 1) {
                    let sql = "CREATE OR REPLACE VIEW employees_branch_1 AS SELECT * from employees where branch=?";
                    con.query(sql, result[0].branch, (err, results) => {
                        const sql = "select * from employees_branch_1";
                        con.query(sql, (err, employees) => {
                            if (employees.length === 0) {
                                res.render("failure", { fail: "no employee found" })
                            } else {
                                res.render("attendance", { employees: employees })
                            }
                        })

                    })
                } else if (result[0].branch === 2) {
                    let sql = "CREATE OR REPLACE VIEW employees_branch_2 AS SELECT * from employees where branch=?";
                    con.query(sql, result[0].branch, (err, results) => {
                        const sql = "select * from employees_branch_2";
                        con.query(sql, (err, employees) => {
                            if (employees.length === 0) {
                                res.render("failure", { fail: "no employee found" })
                            } else {
                                res.render("attendance", { employees: employees })
                            }

                        })

                    })
                } else {
                    let sql = "select * from employees"
                    con.query(sql, (err, results) => {
                        if (err) {
                            res.render("failure", { fail: err })
                        } else {
                            if (results.length === 0) {
                                res.render("failure", { fail: "no employee found" })
                            } else {
                                res.render("attendance", { employees: results })
                            }
                        }
                    })
                }

            }
        })

    } else {
        res.redirect("/");
    }
})

app.post("/attendance", (req, res) => {
    var categories = req.body.category;
    var ids = req.body.id;

    let date = new Date();
    let [tDay] = date.toISOString().split('T')

    let sql = "select * from attendance where employee_id=? and pDate=? ";
    con.query(sql, [ids[0], tDay], (err, result) => {
        if (err) {
            console.log(err);
        }

        if (result.length === 0) {
            ids.forEach((id, index) => {
                var attendance = {
                    employee_id: id,
                    pDate: tDay,
                    status: categories[index],
                }
                const sql1 = "insert into attendance set ?"
                con.query(sql1, attendance, (err, result) => {
                    if (err) {
                        console.log(err);
                    }
                })
            });
            res.redirect("/attendance");
        } else {
            res.render("failure", { fail: "todays attendance already taken" });
        }
    })


})

app.post("/update/attendance", (req, res) => {
    var categories = req.body.category;
    var ids = req.body.id;
    let date = new Date();
    let [tDay] = date.toISOString().split('T');
    ids.forEach((id, index) => {
        let sql = "update attendance set status=? where employee_id=? and pDate=?";
        con.query(sql, [categories[index], id, tDay], (err, result) => {
            if (err) {
                res.render("failure", { fail: err })
            }
        })
    })
    res.redirect("/attendance");
})

app.post("/individual/attendance", (req, res) => {
    var categories = req.body.category;
    var ids = req.body.id;
    let date = new Date();
    let [tDay] = date.toISOString().split('T');
    var empid = req.body.employeeID;
    var pDate = req.body.pDate;
    if (pDate[0] === "") {
        let sql = "select * from attendance where employee_id=? and pDate=?";
        con.query(sql, [empid, tDay], (err, result) => {

            if (err) {
                res.render("failure", { fail: err })
            } else {
                if (result.length === 0) {
                    ids.forEach((eid, index) => {
                        if (eid == empid) {
                            var attendance = {
                                employee_id: eid,
                                pDate: tDay,
                                status: categories[index],
                            }
                            const sql1 = "insert into attendance set ?"
                            con.query(sql1, attendance, (err, result) => {
                                if (err) {
                                    console.log(err);
                                }
                            })
                        }
                    })
                    res.redirect("/attendance");
                } else {
                    ids.forEach((eid, index) => {
                        if (eid == empid) {
                            const sql = "update attendance set status=? where employee_id=? and pDate=?";
                            con.query(sql, [categories[index], eid, tDay], (err, result) => {
                                if (err) {
                                    res.render("failure", { fail: err })
                                } else {
                                    res.redirect("/attendance");
                                }
                            })
                        }
                    })

                }
            }
        })
    } else {
        let cDate = convert(pDate[0]);
        console.log(pDate[0])
        console.log(cDate)
        ids.forEach((id, index) => {
            if (id === empid) {
                let sql = "update attendance set status=? where employee_id=? and pDate=?";
                con.query(sql, [categories[index], id, cDate], (err, result) => {

                    if (err) {
                        console.log(err);

                    }
                })
            }

        })
        res.redirect("/previousAttendance/" + cDate);
    }


})


app.get("/attendance/:empid", (req, res) => {
    const empid = req.params.empid;
    let sql = "select * from attendance a,employees e where a.employee_id=e.employee_id and a.employee_id=?";
    con.query(sql, empid, (err, results) => {

        if (err) {
            res.render("failure", { fail: err })
        } else {
            if (results.length != 0) {
                res.render("specAttendance", { attendances: results });
            } else {
                res.render("failure", { fail: "mark attendance first" })
            }
        }
    })

})

app.post("/delete/attendance", (req, res) => {
    let date = req.body.date

    let empid = req.body.employeeID;
    let sql = 'delete from attendance where employee_id=? and pDate=?';
    con.query(sql, [empid, date], (err, result) => {
        if (err) {
            res.render("failure", { fail: err })
        } else {
            res.redirect("/attendance/" + empid);
        }
    })
})


app.post("/previousAttendance", (req, res) => {
    res.redirect("/previousAttendance/" + req.body.prevDate)
})

app.get("/previousAttendance/:date", (req, res) => {
    if (req.isAuthenticated()) {
        var branch;
        con.query("select * from admins where username=?", req.user.username, (err, result) => {
            branch = result[0].branch;
            var d1 = convert(new Date());

            var d2 = req.params.date;
            if (d2 > d1) {
                res.render("failure", { fail: "future date not possible" })
            } else {
                if (branch === 1) {
                    let sql = "select * from attendance a,employees e where a.employee_id=e.employee_id and a.pDate=? and e.branch=?";
                    con.query(sql, [d2, branch], (err, result) => {
                        if (err) {
                            res.render("failure", { fail: err })
                        } else {
                            if (result.length === 0) {
                                res.render("failure", { fail: "no attendance taken on date:" + d2 })

                            } else {
                                res.render("dynamicDate", { employees: result });

                            }

                        }
                    })
                } else if (branch === 2) {
                    let sql = "select * from attendance a,employees e where a.employee_id=e.employee_id and a.pDate=? and e.branch=?";
                    con.query(sql, [d2, branch], (err, result) => {
                        if (err) {
                            res.render("failure", { fail: err })
                        } else {
                            if (result.length === 0) {
                                res.render("failure", { fail: "no attendance taken on date:" + d2 })
                            } else {
                                res.render("dynamicDate", { employees: result });

                            }

                        }
                    })
                } else {
                    let sql = "select * from attendance a,employees e where a.employee_id=e.employee_id and a.pDate=?";
                    con.query(sql, d2, (err, result) => {
                        if (err) {
                            res.render("failure", { fail: err })
                        } else {
                            if (result.length === 0) {
                                res.render("failure", { fail: "no attendance taken on date:" + d2 })
                            } else {
                                res.render("dynamicDate", { employees: result });

                            }

                        }
                    })
                }

            }
        });


    } else {
        res.redirect("/");
    }

})

/******************************************* salary routes ***************************/

app.get("/salary", (req, res) => {
    if (req.isAuthenticated()) {
        let date = new Date();
        let sql = "select * from employees";
        con.query(sql, (err, result) => {
            if (err) {
                res.render("failure", { fail: err })
            } else {
                result.forEach((emp) => {
                    let sql1 = "select * from salary where  EXTRACT(MONTH FROM month_date)=? and EXTRACT(YEAR FROM month_date)=? and employee_id=?";
                    con.query(sql1, [date.getMonth() + 1, date.getFullYear(), emp.employee_id], (err, results) => {
                        if (results.length === 0) {

                            const sql = "insert into salary set ?";
                            var salary = {
                                month_date: convert(date),
                                paid_status: "unpaid",
                                employee_id: emp.employee_id,
                            }
                            con.query(sql, salary, (err, result) => {

                            })


                        }
                    })

                })

            }
        })
        var branch;
        con.query("select * from admins where username=?", req.user.username, (err, result) => {

            branch = result[0].branch;
            if (branch === 1) {
                let sql2 = "select * from salary s,employees e where s.employee_id=e.employee_id and EXTRACT(MONTH FROM month_date)=? and EXTRACT(YEAR FROM month_date)=? and e.branch=?";
                con.query(sql2, [date.getMonth() + 1, date.getFullYear(), branch], (err, results) => {
                    if (err) {
                        res.render("failure", { fail: err })
                    } else {

                        res.render("salary", { employees: results, date: convert(new Date().toISOString()), month: new Date().getMonth() + 1 })
                    }
                })
            } else if (branch === 2) {
                let sql2 = "select * from salary s,employees e where s.employee_id=e.employee_id and EXTRACT(MONTH FROM month_date)=? and EXTRACT(YEAR FROM month_date)=? and e.branch=?";
                con.query(sql2, [date.getMonth() + 1, date.getFullYear(), branch], (err, results) => {
                    if (err) {
                        res.render("failure", { fail: err })
                    } else {

                        res.render("salary", { employees: results, date: convert(new Date().toISOString()), month: new Date().getMonth() + 1 })
                    }
                })
            } else {
                let sql2 = "select * from salary s,employees e where s.employee_id=e.employee_id and EXTRACT(MONTH FROM month_date)=? and EXTRACT(YEAR FROM month_date)=?";
                con.query(sql2, [date.getMonth() + 1, date.getFullYear(),], (err, results) => {
                    if (err) {
                        res.render("failure", { fail: err })
                    } else {

                        res.render("salary", { employees: results, date: convert(new Date().toISOString()), month: new Date().getMonth() + 1 })
                    }
                })
            }

        });



    } else {
        res.redirect("/")
    }

})

app.post("/salary", (req, res) => {
    let date = new Date(req.body.pDate);
    console.log(date.getMonth());
    console.log(date.getFullYear())
    let empid = req.body.employeeID;
    let sql = "select * from salary where employee_id=? and EXTRACT(MONTH FROM month_date)=? and EXTRACT(YEAR FROM month_date)=? and paid_status=?;";
    con.query(sql, [empid, date.getMonth() + 1, date.getFullYear(), "unpaid"], (err, result) => {

        if (err) {
            res.render("failure", { fail: err })
        } else {
            if (result.length != 0) {
                const sql = "update salary set paid_status='paid' where employee_id=? and EXTRACT(MONTH FROM month_date)=? and EXTRACT(YEAR FROM month_date)=?";

                con.query(sql, [empid, date.getMonth() + 1, date.getFullYear()], (err, result) => {
                    if (err) {
                        res.render("failure", { fail: err })
                    } else {
                        res.redirect("/salary");
                    }
                })
            } else {
                res.redirect("/salary");
            }
        }
    })
})

/********************************* salary history route ***********************/
app.get("/salary/history", (req, res) => {
    if (req.isAuthenticated()) {
        var branch;
        let date = new Date();
        con.query("select * from admins where username=?", req.user.username, (err, result) => {
            branch = result[0].branch;
            if (branch === 1) {
                let sql = "CREATE OR REPLACE VIEW salary_history AS SELECT e.employee_id,e.employee_name,e.salary,e.branch,s.month_date,s.paid_status FROM employees e,salary s where e.employee_id=s.employee_id";
                con.query(sql, (err, result) => {
                    if (err) {
                        res.render("failure", { fail: err })
                    } else {
                        const sql = "select * from salary_history where EXTRACT(MONTH FROM month_date)<=? and EXTRACT(YEAR FROM month_date)<=? and branch=?";
                        con.query(sql, [date.getMonth() + 1, date.getFullYear(), branch], (err, result) => {
                            if (err) {
                                res.render("failure", { fail: err })
                            } else {
                                if (result.length === 0) {
                                    res.render("failure", { fail: "nothing found" })
                                } else {
                                    res.render("salaryHistory", { employees: result, date: convert(new Date().toISOString()) })
                                }
                            }
                        })
                    }
                })
            } else if (branch === 2) {
                let sql = "CREATE OR REPLACE VIEW salary_history AS SELECT e.employee_id,e.employee_name,e.salary,e.branch,s.month_date,s.paid_status FROM employees e,salary s where e.employee_id=s.employee_id";
                con.query(sql, (err, result) => {
                    if (err) {
                        res.render("failure", { fail: err })
                    } else {
                        const sql = "select * from salary_history where EXTRACT(MONTH FROM month_date)<=? and EXTRACT(YEAR FROM month_date)<=? and branch=?";
                        con.query(sql, [date.getMonth() + 1, date.getFullYear(), branch], (err, result) => {
                            if (err) {
                                res.render("failure", { fail: err })
                            } else {
                                if (result.length === 0) {
                                    res.render("failure", { fail: "nothing found" })
                                } else {
                                    res.render("salaryHistory", { employees: result, date: convert(new Date().toISOString()) })
                                }
                            }
                        })
                    }
                })
            } else {
                let sql = "CREATE OR REPLACE VIEW salary_history AS SELECT e.employee_id,e.employee_name,e.salary,e.branch,s.month_date,s.paid_status FROM employees e,salary s where e.employee_id=s.employee_id";
                con.query(sql, (err, result) => {
                    if (err) {
                        res.render("failure", { fail: err })
                    } else {
                        const sql = "select * from salary_history where EXTRACT(MONTH FROM month_date)<=? and EXTRACT(YEAR FROM month_date)<=?";
                        con.query(sql, [date.getMonth() + 1, date.getFullYear()], (err, result) => {
                            if (err) {
                                res.render("failure", { fail: err })
                            } else {
                                if (result.length === 0) {
                                    res.render("failure", { fail: "nothing found" })
                                } else {
                                    res.render("salaryHistory", { employees: result, date: convert(new Date().toISOString()) })
                                }
                            }
                        })
                    }
                })
            }
        })

    }
})

/**************************************** daily sales route *****************************/

app.get("/dailysales", (req, res) => {
    if (req.isAuthenticated()) {
        var branch;
        con.query("select * from admins where username=?", req.user.username, (err, result) => {
            branch = result[0].branch;
            if (branch === 1 || branch === 2) {
                let sql = "select * from service where serviceDate=? and branch=?";
                con.query(sql, [convert(new Date().toISOString()), branch], (err, services) => {

                    if (err) {
                        res.render("failure", { fail: err })
                    } else {
                        con.query("select * from dailysales where sale_day=? and branch=?", [convert(new Date().toISOString()), branch], (err, dailySale) => {

                            if (dailySale.length === 0) {
                                const sql = "call cal_daily_sale(?,?)";
                                con.query(sql, [convert(new Date().toISOString()), branch], (err, result) => {
                                    res.redirect("/dailysales");
                                })
                            } else {
                                if (dailySale[0].total == null) {
                                    res.render("dailysales", { services: services, total: "" });
                                } else {
                                    res.render("dailysales", { services: services, total: dailySale[0].total });
                                }
                            }
                        })

                    }
                })
            } else {
                let sql = "select * from service where serviceDate=?";
                con.query(sql, convert(new Date().toISOString()), (err, services) => {
                    if (err) {
                        res.render("failure", { fail: err })
                    } else {
                        con.query("select sum(total) as total from dailysales where sale_day=?", convert(new Date().toISOString()), (err, sale) => {
                            console.log(sale);
                            res.render("dailysales", { services: services, total: sale[0].total });
                        })

                    }
                })
            }
        })

    } else {
        res.redirect("/");
    }

})
/*************************************** daily sale history route ************************/
app.get("/dailyrecord/:day", (req, res) => {
    if (req.isAuthenticated()) {
        const day = req.params.day;
        const date = new Date;
        var branch;
        con.query("select * from admins where username=?", req.user.username, (err, result) => {
            branch = result[0].branch;
            if (branch === 1 || branch === 2) {
                let sql = "select * from service where EXTRACT(DAY FROM serviceDate)=? and EXTRACT(MONTH FROM serviceDate)=? and EXTRACT(YEAR FROM serviceDate)=? and branch=?";
                con.query(sql, [day, date.getMonth() + 1, date.getFullYear(), branch], (err, services) => {
                    if (err) {
                        res.render("failure", { fail: err })
                    } else {
                        if (services.length === 0) {
                            res.render("failure", { fail: "register serivce first" })
                        } else {
                            con.query("select * from dailysales where EXTRACT(DAY FROM sale_day)=? and EXTRACT(MONTH FROM sale_day)=? and EXTRACT(YEAR FROM sale_day)=? and branch=?", [day, date.getMonth() + 1, date.getFullYear(), branch], (err, dailySale) => {

                                if (dailySale.length === 0) {
                                    const sql = "call cal_daily_sale(?,?)";
                                    con.query(sql, [convert(new Date().toISOString()), branch], (err, result) => {
                                        res.redirect("/dailyrecord/" + day);
                                    })
                                } else {
                                    if (dailySale[0].total == null) {
                                        res.render("failure", { fail: "enter your fisr service" })
                                    } else {
                                        res.render("dailysales", { services: services, total: dailySale[0].total });
                                    }
                                }
                            })
                        }
                    }
                })
            } else {
                let sql = "select * from service where EXTRACT(DAY FROM serviceDate)=? and EXTRACT(MONTH FROM serviceDate)=? and EXTRACT(YEAR FROM serviceDate)=?";
                con.query(sql, [day, date.getMonth() + 1, date.getFullYear()], (err, services) => {
                    if (err) {
                        res.render("failure", { fail: err })
                    } else {
                        if (services.length === 0) {
                            res.render("failure", { fail: "register service first" })
                        } else {
                            con.query("select sum(total) as total  from dailysales where EXTRACT(DAY FROM sale_day)=? and EXTRACT(MONTH FROM sale_day)=? and EXTRACT(YEAR FROM sale_day)=?", [day, date.getMonth() + 1, date.getFullYear()], (err, dailySale) => {

                                if (dailySale.length === 0) {
                                    const sql = "call cal_daily_sale(?,?)";
                                    con.query(sql, [convert(new Date().toISOString()), branch], (err, result) => {
                                        res.redirect("/dailyrecord/" + day);
                                    })
                                } else {
                                    if (dailySale[0].total == null) {
                                        res.render("failure", { fail: "enter your first service plz" })
                                    } else {
                                        res.render("dailysales", { services: services, total: dailySale[0].total });
                                    }
                                }
                            })
                        }
                    }
                })
            }
        })
    } else {
        res.redirect("/");
    }


})
app.get("/monthlySales",(req,res)=>{
    if(req.isAuthenticated()){
        con.query("select findAdmin(?) as branch",req.user.username,(err,result)=>{
            const branch=result[0].branch;
            if(branch===1 || branch===2 ){
                let sql="select * from service where EXTRACT(MONTH FROM serviceDate)=? and EXTRACT(YEAR FROM serviceDate)=? and branch=?";
                con.query(sql,[new Date().getMonth()+1,new Date().getFullYear(),branch],(err,serivces)=>{
                    con.query("select monthlyTot(?,?,?) as total",[branch,new Date().getMonth()+1,new Date().getFullYear()],(err,total)=>{
                        if(serivces.length===0){
                            res.render("monthlySales",{services:serivces,total:0,month:new Date().getMonth()+1});
                        }else{
                            res.render("monthlySales",{services:serivces,total:total[0].total,month:new Date().getMonth()+1});
                        }
                    })
                })
            }else{
                let sql="select * from service where EXTRACT(MONTH FROM serviceDate)=? and EXTRACT(YEAR FROM serviceDate)=?";
                con.query(sql,[new Date().getMonth()+1,new Date().getFullYear(),branch],(err,serivces)=>{
                    con.query("select monthlyTot(?,?,?) as total",[branch,new Date().getMonth()+1,new Date().getFullYear()],(err,total)=>{
                        if(serivces.length===0){
                            res.render("monthlySales",{services:serivces,total:0,month:new Date().getMonth()+1});
                        }else{
                            res.render("monthlySales",{services:serivces,total:total[0].total,month:new Date().getMonth()+1});
                        }
                    })
                })
            }
        })

    }else{
        res.redirect("/");
    }

   

})

app.listen(process.env.PORT || 3000, function (req, res) {
    console.log("server is running at port 3000 enjoy");
})