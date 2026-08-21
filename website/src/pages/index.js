import React from 'react';
import Link from '@docusaurus/Link';
import Layout from '@theme/Layout';
import Translate, {translate} from '@docusaurus/Translate';
import './home.css';

export default function Home() {
  return (
    <Layout title="go-bitfs" description={translate({id: 'home.description', message: 'Source-driven BitFS v4 SDK documentation'})}>
      <main>
        <section className="hero hero--protocol">
          <div className="hero__grain" aria-hidden="true" />
          <div className="container hero__inner">
            <p className="eyebrow"><Translate id="home.eyebrow">BITFS V3 · GO SDK</Translate></p>
            <h1><Translate id="home.heroTitleTop">Protocol truth,</Translate><br /><span><Translate id="home.heroTitleBottom">kept executable.</Translate></span></h1>
            <p className="hero__lede"><Translate id="home.heroLede">Build interoperable file exchange and 2-of-3 settlement workflows from deterministic CBOR, signed credentials, and source-generated APIs.</Translate></p>
            <div className="hero__actions">
              <Link className="button button--amber" to="/docs/sdk/protocol-foundations-and-cbor"><Translate id="home.start">Start with the SDK</Translate></Link>
              <Link className="button button--ghost" to="/api/"><Translate id="home.api">Browse API reference</Translate></Link>
            </div>
            <div className="hero__signal" aria-hidden="true"><span /><Translate id="home.signal">quote → pool → content → payment</Translate></div>
          </div>
        </section>
        <section className="container flow-section">
          <div className="flow-intro"><p className="eyebrow"><Translate id="home.flowEyebrow">ONE CONSISTENT FLOW</Translate></p><h2><Translate id="home.flowTitle">From signed quote to settled content.</Translate></h2><p><Translate id="home.flowLede">Each package owns one boundary. Keep application infrastructure outside the protocol core and pass exact bytes between roles.</Translate></p></div>
          <ol className="flow-list">
            <li><span>01</span><strong><Translate id="home.quote">Quote</Translate></strong><em><Translate id="home.quoteDetail">Seller signs terms</Translate></em></li>
            <li><span>02</span><strong><Translate id="home.open">Open</Translate></strong><em><Translate id="home.openDetail">Buyer and seller fund the pool</Translate></em></li>
            <li><span>03</span><strong><Translate id="home.deliver">Deliver</Translate></strong><em><Translate id="home.deliverDetail">Content is verified against its request</Translate></em></li>
            <li><span>04</span><strong><Translate id="home.settle">Settle</Translate></strong><em><Translate id="home.settleDetail">Cumulative payment closes the loop</Translate></em></li>
          </ol>
        </section>
        <section className="container home-cta"><p className="eyebrow"><Translate id="home.referenceEyebrow">SOURCE-DRIVEN REFERENCE</Translate></p><h2><Translate id="home.referenceTitle">Read the implementation, not a mirror.</Translate></h2><p><Translate id="home.referenceLede">API pages are generated from the Go packages used in production. Guides explain how to compose them.</Translate></p><Link className="text-link" to="/docs/sdk/role-workflow-api"><Translate id="home.workflows">Explore role workflows</Translate> <span>↗</span></Link></section>
      </main>
    </Layout>
  );
}
