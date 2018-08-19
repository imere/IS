const express = require('express')
const bodyParser = require('body-parser')
const helmet = require('helmet')
const fs = require('fs')
const bcrypt = require('bcrypt')

const PORT = process.env.PORT || 8000

const app = express()

app.use(bodyParser.json({
  type: ['json', 'application/csp-report']
}))

/*
 * X-Powered-By: Express is sent in every request coming from Express
 * by default. The helmet.hidePoweredBy() middleware will remove
 * the X-Powered-By header. You can also explicitly set the header to
 * something else, e.g. app.use(helmet.hidePoweredBy({ setTo: 'PHP 4.2.0' }))
 */
app.use(helmet.hidePoweredBy({
  setTo: 'nginx'
}))

/*
 * We don’t need our app to be framed.You should use helmet.frameguard()
 * passing with the configuration object {action: 'deny'}.
 */
app.use(helmet.frameguard({
  action: 'deny'
}))

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
app.use(helmet.hsts({
  maxAge: 10000,
  force: true
}))

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

/*
 * Disable Client-Side Caching
 */
app.use(helmet.noCache())

/*
 * CSP works by defining a whitelist of content sources which are trusted. You
 * can configure them for each kind of resource a web page may need (scripts,
 * stylesheets, fonts, frames, media, and so on…). There are multiple directives
 * available, so a website owner can have a granular control. See HTML 5 Rocks,
 * KeyCDN for more details. Unfortunately CSP is unsupported by older browser.
 * By default, directives are wide open, so it’s important to set the defaultSrc
 * directive as a fallback. Helmet supports both defaultSrc and default-src naming
 * styles. The fallback applies for most of the unspecified directives. Configure
 * it setting the defaultSrc directive to ["self"] (the list of allowed sources
 * must be in an array), in order to trust only your website address by default.
 * Set also the scriptSrc directive so that you will allow scripts to be downloaded
 * from your website, and from the domain 'trusted-cdn.com'.
 * In the "'self'" keyword, the single quotes are part of the keyword itself, so
 * it needs to be enclosed in double quotes to be working.
 */
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'"],
    // styleSrc: ["'self", "'unsafe-inline'"], // comment for violation report test
    imgSrc: ["'self'"],
    reportUri: '/report-violation'
  }
}))

app.get('*', (req, res) => {
  // res.setHeader('X-Frame-Options', 'DENY') // alternative to helmet.frameguard()
  // res.setHeader('X-XSS-Protection', '1; mode=block') // alternative to helmet.xssFilter()
  // res.setHeader('X-Content-Type-Options', 'nosniff') // alternative to helmet.noSniff()
  // res.setHeader('X-Download-Options', 'noopen') // alternative to helmet.ieNoOpen()
  // res.setHeader('Strict-Transport-Security', 'max-age=1000; includeSubDomain') // alternative to helmet.hsts()
  // res.setHeader('X-DNS-Prefetch-Control', 'off') // alternative to helmet.dnsPrefetchControl()
  // res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate')
  // res.setHeader('Pragma', 'no-cache')
  // res.setHeader('Surrogate-Control', 'no-store')
  // res.setHeader('Expires', '0') // alternative to helmet.noCache()
  // res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; report-uri /report-violation") // alternative to helmet.contentSecurityPolicy()
  res.setHeader('Content-Type', 'text/html')
  res.end(fs.readFileSync('./index.html'))
  bcrypt.hash('data', 13, (err, d) => {
    console.log(d)
    bcrypt.compare('data', d, (err, b) => {
      console.log(b)
    })
  })
  const d = bcrypt.hashSync('data', 13)
  const b = bcrypt.compareSync('data', d)
  console.log(d, b)
})

app.post('/report-violation', (req, res) => {
  console.log('Violation: ', req.body)
  res.status(204).end()
})

const server = app.listen(PORT, () => {
  console.log(`
    Listening on ${server.address().address + ':' + server.address().port}
  `)
});
