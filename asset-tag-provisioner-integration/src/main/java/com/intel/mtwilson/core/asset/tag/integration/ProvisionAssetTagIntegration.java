/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.asset.tag.integration;

import com.intel.dcsg.cpg.extensions.WhiteboardExtensionProvider;
import com.intel.dcsg.cpg.tls.policy.TlsPolicy;
import com.intel.dcsg.cpg.tls.policy.impl.InsecureTlsPolicy;
import com.intel.kunit.annotations.*;
import com.intel.mtwilson.core.asset.tag.ProvisionAssetTag;
import com.intel.mtwilson.core.host.connector.*;
import com.intel.mtwilson.core.host.connector.intel.IntelHostConnectorFactory;
import com.intel.mtwilson.core.host.connector.intel.MicrosoftHostConnectorFactory;
import com.intel.mtwilson.core.host.connector.vmware.VmwareHostConnectorFactory;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author hmgowda
 */
public class ProvisionAssetTagIntegration {

    final TlsPolicy tlsPolicy = new InsecureTlsPolicy();

//    @Integration(parameters = {
//        "intel:https://192.168.0.1:1443;u=tagentadmin;p=TAgentAdminPassword",
//        "649f1f1bb2aa40d09721413e120ac80d8c39698abd296b23de8ff3f8cb83b612"
//    })
    /**
     *
     * @param hostConn
     * @param sha256Digest
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    @Integration
    public void provisionTagCertificateWithSha256(String hostConn, String sha256Digest) throws IOException, NoSuchAlgorithmException {

        WhiteboardExtensionProvider.register(VendorHostConnectorFactory.class, IntelHostConnectorFactory.class);
        WhiteboardExtensionProvider.register(VendorHostConnectorFactory.class, MicrosoftHostConnectorFactory.class);
        WhiteboardExtensionProvider.register(VendorHostConnectorFactory.class, VmwareHostConnectorFactory.class);
        ProvisionAssetTag provisionTag = new ProvisionAssetTag();
        provisionTag.provisionTagCertificate(hostConn, sha256Digest, tlsPolicy);
    }

//    @Integration(parameters = {
//        "intel:https://192.168.0.1:1443;u=tagentadmin;p=TAgentAdminPassword",
//        [1,2,3,4,5,6,7,8,9,0,1]
//    })
    /**
     *
     * @param hostConn
     * @param certificate
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    @Integration
    public void provisionTagCertificateWithCertificate(String hostConn, byte[] certificate) throws IOException, NoSuchAlgorithmException {

        WhiteboardExtensionProvider.register(VendorHostConnectorFactory.class, IntelHostConnectorFactory.class);
        WhiteboardExtensionProvider.register(VendorHostConnectorFactory.class, MicrosoftHostConnectorFactory.class);
        WhiteboardExtensionProvider.register(VendorHostConnectorFactory.class, VmwareHostConnectorFactory.class);        
        ProvisionAssetTag provisionTag = new ProvisionAssetTag();
        provisionTag.provisionTagCertificate(hostConn, certificate, tlsPolicy);
    }
}
