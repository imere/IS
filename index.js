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

/*
 * HTTP Strict Transport Security (HSTS) is a web security policy which
 * helps to protect websites against protocol downgrade attacks and
 * cookie hijacking. This will work for the requests coming after the
 * initial request.
 * Configure helmet.hsts() to use HTTPS for the next 90 days. Pass the
 * config object { maxAge: timeInMilliseconds, force: true }. Set the
 * field "force" to true in the config object, we will intercept and restore
 * the header.
 * Configuring HTTPS on a custom website requires the acquisition of
 * a domain, and a SSL/TSL Certificate.
 */
app.use(helmet.hsts({ maxAge: 10000, force: true }))

/*
 * To improve performance, most browsers prefetch DNS records for the links
 * in a page. In that way the destination ip is already known when the user
 * clicks on a link. This may lead to over-use of the DNS service (if you
 * own a big website, visited by millions people…), privacy issues (one
 * eavesdropper could infer that you are on a certain page), or page statistics
 * alteration (some links may appear visited even if they are not). If you
 * have high security needs you can disable DNS prefetching, at the cost of
 * a performance penalty.
 */
app.use(helmet.dnsPrefetchControl())

app.get('*', (req, res) => {
  // res.setHeader('X-Frame-Options', 'DENY') // alternative to helmet.frameguard()
  // res.setHeader('X-XSS-Protection', '1; mode=block') // alternative to helmet.xssFilter()
  // res.setHeader('X-Content-Type-Options', 'nosniff') // alternative to helmet.noSniff()
  // res.setHeader('X-Download-Options', 'noopen') // alternative to helmet.ieNoOpen()
  // res.setHeader('Strict-Transport-Security', 'max-age=1000; includeSubDomain') // alternative to helmet.hsts()
  // res.setHeader('X-DNS-Prefetch-Control', 'off') // alternative to helmet.dnsPrefetchControl()
  res.setHeader('Content-Type', 'text/html')
  res.end(fs.readFileSync('./index.html'))
})

const server = app.listen(PORT, () => {
  console.log(server.address())
  console.log(`
    Listening on ${server.address().address + ':' + server.address().port}
  `)
});
