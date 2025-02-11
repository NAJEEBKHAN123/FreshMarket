const express = require('express')
const DBconnection = require('./db')
const app = express();
require('dotenv').config();
const authRoute = require('./Routes/authRoute')
const cors = require('cors')
const errorHandler = require('./middleware/errorMiddleware')



//database connection
DBconnection();

//middleware
app.use(express.json());
app.use(cors());
app.use(errorHandler);


const PORT = process.env.PORT || 3000
app.get('/', (req, res) =>{
    res.send("homemmmm")
})

app.use('/api/auth', authRoute)

app.listen(PORT, () =>{
    console.log(`server is listing on http://localhost:${PORT}`)
})