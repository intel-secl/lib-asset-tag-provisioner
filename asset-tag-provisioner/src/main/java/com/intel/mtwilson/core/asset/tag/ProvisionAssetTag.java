/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.asset.tag;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.crypto.Sha384Digest;
import com.intel.dcsg.cpg.tls.policy.TlsPolicy;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import com.intel.mtwilson.configuration.ConfigurationProvider;
import com.intel.mtwilson.core.common.utils.AASConstants;
import com.intel.mtwilson.core.host.connector.HostConnector;
import com.intel.mtwilson.core.host.connector.HostConnectorFactory;
import java.io.IOException;

/**
 *
 * This class is used to provision asset tags on the host (windows and RHEL
 * hosts) given the host connection string, the asset tag certificate or the
 * sha384 digest of the certificate and the TlsPolicy of the host
 *
 * @author hmgowda
 *
 * Since 1.0
 */
public class ProvisionAssetTag {
    
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(ProvisionAssetTag.class);

    private String getCertSha384(byte[] certificate) {

        String sha384DigestValue = Sha384Digest.digestOf(certificate).toString();
        return sha384DigestValue;
    }

    /**
     * This function is used to call the host connector library with the asset
     * tag certificate SHA384, host connection string and the TlsPolicy object
     *
     * @param hostConn Host connection String
     * @param aasApiUrl
     * @param sha384Digest Sha5256 Digest of the AssetTag Certificate
     * @param tlsPolicy tlsPolicy object for the host
     * @since CIT Next Gen
     *<pre>
     *<b>Returns</b>
     *void
     *
     *<b>Sample API Call:</b>
     *   ProvisionAssetTag provisionTag = new ProvisionAssetTag();
     *   provisionTag.proivisionTagCertificate("Intel:https://192.168.0.1:1443/u=admin;p=password","649f1f1bb2aa40d09721413e120ac80d8c39698abd296b23de8ff3f8cb83b65a",tlsPolicyObj)
     *</pre>
     *
     * @throws IOException The function throws IOException
     */
    //The format of hostconnection string is Intel:https://192.168.0.1:1443/u=admin;p=password(serverType:https://serverIP:portnumber/;u=uname;p=password)
    public void provisionTagCertificate(String hostConn, String aasApiUrl, String sha384Digest, TlsPolicy tlsPolicy) throws IOException {

        log.debug("The sha384 value of the AssetTag certificate we are trying to provision is: "+sha384Digest);
        Sha384Digest certSha384 = Sha384Digest.valueOf(sha384Digest);
        log.debug("Calling the host Connector library setAssetTAg method to provision the asset tag");
        HostConnectorFactory factory = new HostConnectorFactory();
        HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);
        hostConnector.setAssetTagSha384(certSha384);
    }

    /**
     * This function is used to call the host connector library with the asset
     * tag certificate, host connection string and the TlsPolicy Object
     *
     * @param hostConn Host connection String
     * @param aasApiUrl
     * @param certificate Asset tag certificate in byte array format
     * @param tlsPolicy tlsPolicy object for the host
     * @since CIT Next Gen
     *<pre>
     *<b>Returns</b>
     * void
     *
     *<b>Sample API Call:</b>
     *   ProvisionAssetTag provisionTag = new ProvisionAssetTag();
     *   provisionTag.proivisionTagCertificate("Intel:https://192.168.0.1:1443/u=admin;p=password",{subject=.......},tlsPolicyObj)
     *</pre>
     *
     * @throws IOException The function throws IOException
     */
    public void provisionTagCertificate(String hostConn, String aasApiUrl, byte[] certificate, TlsPolicy tlsPolicy) throws IOException {

        String sha384Digest = getCertSha384(certificate);

        Sha384Digest certSha384 = Sha384Digest.valueOf(sha384Digest);
        log.debug("The sha384 value of the AssetTag certificate we are trying to provision is: "+certSha384.toString());
        log.debug("Calling the host Connector library setAssetTag method to provision the asset tag");
        HostConnectorFactory factory = new HostConnectorFactory();

        HostConnector hostConnector = factory.getHostConnector(hostConn, aasApiUrl, tlsPolicy);
        hostConnector.setAssetTagSha384(certSha384);

    }
}
