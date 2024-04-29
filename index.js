const express = require('express')
const app = express()
const port = 3000
const cors = require('cors');
const { generateTonProofPayload } = require('./controller/generate');
const { check } = require('./controller');

app.use(cors())
app.use(express.json())
app.use(express.urlencoded({ extended: true }));

app.get('/ton-proof/generatePayload', generateTonProofPayload);

app.post('/ton-proof/checkProof', check);


app.get('/', (req, res) => {
    res.send('Hello World!')
})

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})