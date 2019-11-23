//jshint esversion:6

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
const dotenv = require('dotenv')
const homeStartingContent = "Lacus vel facilisis volutpat est velit egestas dui id ornare. Semper auctor neque vitae tempus quam. Sit amet cursus sit amet dictum sit amet justo. Viverra tellus in hac habitasse. Imperdiet proin fermentum leo vel orci porta. Donec ultrices tincidunt arcu non sodales neque sodales ut. Mattis molestie a iaculis at erat pellentesque adipiscing. Magnis dis parturient montes nascetur ridiculus mus mauris vitae ultricies. Adipiscing elit ut aliquam purus sit amet luctus venenatis lectus. Ultrices vitae auctor eu augue ut lectus arcu bibendum at. Odio euismod lacinia at quis risus sed vulputate odio ut. Cursus mattis molestie a iaculis at erat pellentesque adipiscing.";
const aboutContent = "Hac habitasse platea dictumst vestibulum rhoncus est pellentesque. Dictumst vestibulum rhoncus est pellentesque elit ullamcorper. Non diam phasellus vestibulum lorem sed. Platea dictumst quisque sagittis purus sit. Egestas sed sed risus pretium quam vulputate dignissim suspendisse. Mauris in aliquam sem fringilla. Semper risus in hendrerit gravida rutrum quisque non tellus orci. Amet massa vitae tortor condimentum lacinia quis vel eros. Enim ut tellus elementum sagittis vitae. Mauris ultrices eros in cursus turpis massa tincidunt dui.";
const contactContent = "Scelerisque eleifend donec pretium vulputate sapien. Rhoncus urna neque viverra justo nec ultrices. Arcu dui vivamus arcu felis bibendum. Consectetur adipiscing elit duis tristique. Risus viverra adipiscing at in tellus integer feugiat. Sapien nec sagittis aliquam malesuada bibendum arcu vitae. Consequat interdum varius sit amet mattis. Iaculis nunc sed augue lacus. Interdum posuere lorem ipsum dolor sit amet consectetur adipiscing elit. Pulvinar elementum integer enim neque. Ultrices gravida dictum fusce ut placerat orci nulla. Mauris in aliquam sem fringilla ut morbi tincidunt. Tortor posuere ac ut consequat semper viverra nam libero.";
const postRoute = require('./routes/posts')
    // import auth routes
const authRoute = require('./routes/auth');

const verify = require('./routes/verifyToken');
const app = express();
const router = require('express').Router();
const User = require('./model/User')

dotenv.config();

app.set('view engine', 'ejs');
app.use(express.json())
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));




// router middlewares
app.use('/', authRoute)
app.use('/api/posts', postRoute)
    // mongoose.connect("mongodb://localhost:27017/blogDB", { useNewUrlParser: true, useUnifiedTopology: true });
    // 
mongoose.connect(process.env.DB_CONNECT, {
        useNewUrlParser: true,
        useUnifiedTopology: true
    }, () => console.log('connected to the db!'))
    // 

const postSchema = {
    img: String,
    title: String,
    content: String
};


const Post = mongoose.model("Post", postSchema);

app.get("/", (req, res) => {

    Post.find({}, (err, posts) => {
        res.render("home", {
            startingContent: homeStartingContent,
            posts: posts
        });
    });





    if (res.header !== null || undefined) {}
});

app.get("/compose", verify, (req, res) => {
    res.render("compose");
});

app.post("/compose", (req, res) => {
    const post = new Post({
        img: req.body.postImg,
        title: req.body.postTitle,
        content: req.body.postBody
    });


    post.save((err) => {
        if (!err) {
            res.redirect("/");
        }
    });
});

app.get("/posts/:postId", (req, res) => {

    const requestedPostId = req.params.postId;

    Post.findOne({ _id: requestedPostId }, (err, post) => {
        res.render("post", {
            img: post.img,
            title: post.title,
            content: post.content
        });
    });

});

app.get("/about", (req, res) => {
    res.render("about", { aboutContent: aboutContent });
});

app.get("/contact", (req, res) => {
    res.render("contact", { contactContent: contactContent });
});

app.get('/login', (req, res) => {
    res.render('login.ejs')
})

// app.post('/api/user/login', (req, res) => {
//     const user = new User({
//         email: req.body.email,
//         password: req.body.password
//     });
//     app.render('/')
// })


app.get('/register', (req, res) => {
    res.render('register.ejs')
})


// app.listen(3000, () => {
//     console.log("Server started on port 3000");
// });

var server = app.listen(process.env.PORT || 5000, function() {
    var port = server.address().port;
    console.log("Express is working on port " + port);
});