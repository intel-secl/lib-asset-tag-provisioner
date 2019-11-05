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

    /**
     *
     * @param hostConn
     * @param sha384Digest
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    @Integration
    public void provisionTagCertificateWithSha384(String hostConn, String aasApiUrl, String sha384Digest) throws IOException, NoSuchAlgorithmException {

        WhiteboardExtensionProvider.register(VendorHostConnectorFactory.class, IntelHostConnectorFactory.class);
        WhiteboardExtensionProvider.register(VendorHostConnectorFactory.class, MicrosoftHostConnectorFactory.class);
        WhiteboardExtensionProvider.register(VendorHostConnectorFactory.class, VmwareHostConnectorFactory.class);
        ProvisionAssetTag provisionTag = new ProvisionAssetTag();
        provisionTag.provisionTagCertificate(hostConn, aasApiUrl, sha384Digest, tlsPolicy);
    }

    /**
     *
     * @param hostConn
     * @param certificate
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    @Integration
    public void provisionTagCertificateWithCertificate(String hostConn, String aasApiUrl, byte[] certificate) throws IOException, NoSuchAlgorithmException {

        WhiteboardExtensionProvider.register(VendorHostConnectorFactory.class, IntelHostConnectorFactory.class);
        WhiteboardExtensionProvider.register(VendorHostConnectorFactory.class, MicrosoftHostConnectorFactory.class);
        WhiteboardExtensionProvider.register(VendorHostConnectorFactory.class, VmwareHostConnectorFactory.class);        
        ProvisionAssetTag provisionTag = new ProvisionAssetTag();
        provisionTag.provisionTagCertificate(hostConn, aasApiUrl, certificate, tlsPolicy);
    }
}
