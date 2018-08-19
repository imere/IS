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

/*
 * Browsers can use content or MIME sniffing to adapt to different
 * datatypes coming from a response. They override the Content-Type
 * headers to guess and process the data. While this can be convenient
 * in some scenarios, it can also lead to some dangerous attacks.
 * This middleware sets the X-Content-Type-Options header to nosniff.
 * This instructs the browser to not bypass the provided Content-Type.
 */
app.use(helmet.noSniff())

/*
 * Some web applications will serve untrusted HTML for download. Some
 * versions of Internet Explorer by default open those HTML files in
 * the context of your site.This middleware sets the X-Download-Options
 * header to noopen. This will prevent IE users from executing downloads
 * in the trusted site’s context.
 */
app.use(helmet.ieNoOpen())

app.get('*', (req, res) => {
  // res.setHeader('X-Frame-Options', 'DENY') // alternative to helmet.frameguard()
  // res.setHeader('X-XSS-Protection', '1; mode=block') // alternative to helmet.xssFilter()
  // res.setHeader('X-Content-Type-Options', 'nosniff') // alternative to helmet.noSniff()
  // res.setHeader('X-Download-Options', 'noopen') // alternative to helmet.ieNoOpen()
  res.setHeader('Content-Type', 'text/html')
  res.end(fs.readFileSync('./index.html'))
})

const server = app.listen(PORT, () => {
  console.log(server.address())
  console.log(`
    Listening on ${server.address().address + ':' + server.address().port}
  `)
});
