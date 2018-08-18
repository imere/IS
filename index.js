const express = require('express')
const helmet = require('helmet')

const PORT = process.env.PORT || 8000

const app = express()

/*
 * X-Powered-By: Express is sent in every request coming from Express
 * by default. The helmet.hidePoweredBy() middleware will remove
 * the X-Powered-By header. You can also explicitly set the header to
 * something else, e.g. app.use(helmet.hidePoweredBy({ setTo: 'PHP 4.2.0' }))
 */
app.use(helmet.hidePoweredBy({ setTo: 'nginx' }))

app.get('*', (req, res) => {
  res.end()
})

const server = app.listen(PORT, () => {
  console.log(`
    Listening on port ${server.address().port}
  `)
})
