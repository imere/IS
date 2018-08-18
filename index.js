const express = require('express')
const helmet = require('helmet')
const fs = require('fs')

const PORT = process.env.PORT || 8000

const app = express()

/*
 * X-Powered-By: Express is sent in every request coming from Express
 * by default. The helmet.hidePoweredBy() middleware will remove
 * the X-Powered-By header. You can also explicitly set the header to
 * something else, e.g. app.use(helmet.hidePoweredBy({ setTo: 'PHP 4.2.0' }))
 */
app.use(helmet.hidePoweredBy({ setTo: 'nginx' }))

/*
 * We don’t need our app to be framed.You should use helmet.frameguard()
 * passing with the configuration object {action: 'deny'}.
 */
app.use(helmet.frameguard({ action: 'deny' }))

/*
 * The X-XSS-Protection HTTP header is a basic protection. The browser
 * detects a potential injected script using a heuristic filter. If the
 * header is enabled, the browser changes the script code, neutralizing it.
 * It still has limited support.
 */
app.use(helmet.xssFilter())

app.get('*', (req, res) => {
  // res.setHeader('X-Frame-Options', 'DENY') // alternative to helmet.frameguard()
  // res.setHeader('X-XSS-Protection', '1; mode=block') // alternative to helmet.xssFilter()
  res.end(fs.readFileSync('./index.html'))
})

const server = app.listen(PORT, () => {
  console.log(`
    Listening on port ${server.address().port}
  `)
})
