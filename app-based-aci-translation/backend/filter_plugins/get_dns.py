#!/usr/bin/python

from ansible.utils.display import Display
import collections, re, json
CLASS_MAP = {"aaaUserDomain": "aci_user_security_domain.translated_user_security_domain", "rtctrlMatchCommTerm": "aci_match_community_terms.translated_match_community_terms", "fvAEPg": "aci_application_epg.translated_application_epg", "isisDomPol": "aci_isis_domain_policy.translated_isis_domain_policy", "mgmtConnectivityPrefs": "aci_mgmt_preference.translated_mgmt_preference", "l3extDomP": "aci_l3_domain_profile.translated_l3_domain_profile", "infraAccNodePGrp": "aci_access_switch_policy_group.translated_access_switch_policy_group", "pkiExportEncryptionKey": "aci_encryption_key.translated_encryption_key", "firmwareFwGrp": "aci_firmware_group.translated_firmware_group", "vnsLDevCtx": "aci_logical_device_context.translated_logical_device_context", "fvCtx": "aci_vrf.translated_vrf", "infraAccPortP": "aci_leaf_interface_profile.translated_leaf_interface_profile", "tacacsSrc": "aci_tacacs_source.translated_tacacs_source", "vzTaboo": "aci_taboo_contract.translated_taboo_contract", "trigRecurrWindowP": "aci_recurring_window.translated_recurring_window", "aaaLdapGroupMap": "aci_ldap_group_map.translated_ldap_group_map", "lacpLagPol": "aci_lacp_policy.translated_lacp_policy", "aaaDefaultAuth": "aci_default_auth.translated_default_auth", "bfdIfP": "aci_l3out_bfd_interface_profile.translated_l3out_bfd_interface_profile", "fabricNodeBlk": "aci_node_block_firmware.translated_node_block_firmware", "configExportP": "aci_configuration_export_policy.translated_configuration_export_policy", "fvTenant": "aci_tenant.translated_tenant", "snmpCtxP": "aci_vrf_snmp_context.translated_vrf_snmp_context", "bgpCtxAfPol": "aci_bgp_address_family_context.translated_bgp_address_family_context", "fileRemotePath": "aci_file_remote_path.translated_file_remote_path", "infraSubPortBlk": "aci_access_sub_port_block.translated_access_sub_port_block", "infraRsSpAccPortP": "aci_spine_interface_profile_selector.translated_spine_interface_profile_selector", "aaaDomain": "aci_aaa_domain.translated_aaa_domain", "cdpIfPol": "aci_cdp_interface_policy.translated_cdp_interface_policy", "ospfCtxPol": "aci_ospf_timers.translated_ospf_timers", "mgmtInB": "aci_node_mgmt_epg.translated_node_mgmt_epg", "hsrpIfP": "aci_l3out_hsrp_interface_profile.translated_l3out_hsrp_interface_profile", "vzEntry": "aci_filter_entry.translated_filter_entry", "firmwareOSource": "aci_firmware_download_task.translated_firmware_download_task", "lldpIfPol": "aci_lldp_interface_policy.translated_lldp_interface_policy", "tagAnnotation": "aci_annotation.translated_annotation", "fabricNodeIdentP": "aci_fabric_node_member.translated_fabric_node_member", "fvSubnet": "aci_subnet.translated_subnet", "infraPortBlk": "aci_access_port_block.translated_access_port_block", "bfdIfPol": "aci_bfd_interface_policy.translated_bfd_interface_policy", "aaaSamlProviderGroup": "aci_saml_provider_group.translated_saml_provider_group", "snmpCommunityP": "aci_vrf_snmp_context_community.translated_vrf_snmp_context_community", "infraSpineP": "aci_spine_profile.translated_spine_profile", "aaaProviderRef": "aci_login_domain_provider.translated_login_domain_provider", "infraRsFuncToEpg": "aci_epgs_using_function.translated_epgs_using_function", "infraNodeP": "aci_leaf_profile.translated_leaf_profile", "aaaConsoleAuth": "aci_console_authentication.translated_console_authentication", "mgmtGrp": "aci_managed_node_connectivity_group.translated_managed_node_connectivity_group", "tacacsTacacsDest": "aci_tacacs_accounting_destination.translated_tacacs_accounting_destination", "rtctrlProfile": "aci_route_control_profile.translated_route_control_profile", "epControlP": "aci_endpoint_controls.translated_endpoint_controls", "tacacsGroup": "aci_tacacs_accounting.translated_tacacs_accounting", "cloudEPSelector": "aci_cloud_endpoint_selector.translated_cloud_endpoint_selector", "vmmCtrlrP": "aci_vmm_controller.translated_vmm_controller", "fabricHIfPol": "aci_fabric_if_pol.translated_fabric_if_pol", "dhcpRelayP": "aci_dhcp_relay_policy.translated_dhcp_relay_policy", "l2PortSecurityPol": "aci_port_security_policy.translated_port_security_policy", "infraSpineAccNodePGrp": "aci_spine_switch_policy_group.translated_spine_switch_policy_group", "aaaUser": "aci_local_user.translated_local_user", "cloudCidr": "aci_cloud_cidr_pool.translated_cloud_cidr_pool", "cloudExtEPSelector": "aci_cloud_endpoint_selectorfor_external_epgs.translated_cloud_endpoint_selectorfor_external_epgs", "aaaDuoProviderGroup": "aci_duo_provider_group.translated_duo_provider_group", "aaaRsaProvider": "aci_rsa_provider.translated_rsa_provider", "cloudDomP": "aci_cloud_domain_profile.translated_cloud_domain_profile", "fabricNodeControl": "aci_fabric_node_control.translated_fabric_node_control", "l3extMember": "aci_l3out_vpc_member.translated_l3out_vpc_member", "l3extOut": "aci_l3_outside.translated_l3_outside", "infraFexP": "aci_fex_profile.translated_fex_profile", "infraNodeBlk": "aci_node_block.translated_node_block", "bgpRtSummPol": "aci_bgp_route_summarization.translated_bgp_route_summarization", "vnsAbsGraph": "aci_l4_l7_service_graph_template.translated_l4_l7_service_graph_template", "fabricRsOosPath": "aci_interface_blacklist.translated_interface_blacklist", "cloudSubnet": "aci_cloud_subnet.translated_cloud_subnet", "configImportP": "aci_configuration_import_policy.translated_configuration_import_policy", "vnsSvcRedirectPol": "aci_service_redirect_policy.translated_service_redirect_policy", "fvESg": "aci_endpoint_security_group.translated_endpoint_security_group", "mgmtOoBZone": "aci_mgmt_zone.translated_mgmt_zone", "hsrpSecVip": "aci_l3out_hsrp_secondary_vip.translated_l3out_hsrp_secondary_vip", "spanSrcGrp": "aci_span_source_group.translated_span_source_group", "vmmDomP": "aci_vmm_domain.translated_vmm_domain", "aaaTacacsPlusProvider": "aci_tacacs_provider.translated_tacacs_provider", "vnsLIfCtx": "aci_logical_interface_context.translated_logical_interface_context", "l3extInstP": "aci_external_network_instance_profile.translated_external_network_instance_profile", "ospfIfPol": "aci_ospf_interface_policy.translated_ospf_interface_policy", "epIpAgingP": "aci_endpoint_ip_aging_profile.translated_endpoint_ip_aging_profile", "infraSpineS": "aci_spine_switch_association.translated_spine_switch_association", "l3extRsPathL3OutAtt": "aci_l3out_path_attachment.translated_l3out_path_attachment", "fabricExplicitGEp": "aci_vpc_explicit_protection_group.translated_vpc_explicit_protection_group", "rtctrlAttrP": "aci_action_rule_profile.translated_action_rule_profile", "rtctrlSubjP": "aci_match_rule.translated_match_rule", "l3extRouteTagPol": "aci_l3out_route_tag_policy.translated_l3out_route_tag_policy", "qosInstPol": "aci_qos_instance_policy.translated_qos_instance_policy", "infraLeafS": "aci_leaf_selector.translated_leaf_selector", "rtctrlMatchRtDest": "aci_match_route_destination_rule.translated_match_route_destination_rule", "fcIfPol": "aci_interface_fc_policy.translated_interface_fc_policy", "rtctrlCtxP": "aci_route_control_context.translated_route_control_context", "infraRsDomP": "aci_aaep_to_domain.translated_aaep_to_domain", "fvEpRetPol": "aci_end_point_retention_policy.translated_end_point_retention_policy", "aaaAuthRealm": "aci_authentication_properties.translated_authentication_properties", "vzFilter": "aci_filter.translated_filter", "l3extLoopBackIfP": "aci_l3out_loopback_interface_profile.translated_l3out_loopback_interface_profile", "physDomP": "aci_physical_domain.translated_physical_domain", "vpcInstPol": "aci_vpc_domain_policy.translated_vpc_domain_policy", "infraSpAccPortGrp": "aci_spine_port_policy_group.translated_spine_port_policy_group", "vmmUsrAccP": "aci_vmm_credential.translated_vmm_credential", "fvBD": "aci_bridge_domain.translated_bridge_domain", "infraAccPortGrp": "aci_leaf_access_port_policy_group.translated_leaf_access_port_policy_group", "fvRsPathAtt": "aci_epg_to_static_path.translated_epg_to_static_path", "cloudCtxProfile": "aci_cloud_context_profile.translated_cloud_context_profile", "trigSchedP": "aci_trigger_scheduler.translated_trigger_scheduler", "epLoopProtectP": "aci_endpoint_loop_protection.translated_endpoint_loop_protection", "infraSHPortS": "aci_spine_access_port_selector.translated_spine_access_port_selector", "fcDomP": "aci_fc_domain.translated_fc_domain", "mcpIfPol": "aci_miscabling_protocol_interface_policy.translated_miscabling_protocol_interface_policy", "aaaSamlProvider": "aci_saml_provider.translated_saml_provider", "l3extSubnet": "aci_l3_ext_subnet.translated_l3_ext_subnet", "infraHPortS": "aci_access_port_selector.translated_access_port_selector", "l2extInstP": "aci_l2out_extepg.translated_l2out_extepg", "vnsAbsNode": "aci_function_node.translated_function_node", "infraProvAcc": "aci_vlan_encapsulationfor_vxlan_traffic.translated_vlan_encapsulationfor_vxlan_traffic", "infraPortTrackPol": "aci_port_tracking.translated_port_tracking", "l2IfPol": "aci_l2_interface_policy.translated_l2_interface_policy", "l3extLNodeP": "aci_logical_node_profile.translated_logical_node_profile", "infraAccBndlGrp": "aci_leaf_access_bundle_policy_group.translated_leaf_access_bundle_policy_group", "l3extLIfP": "aci_logical_interface_profile.translated_logical_interface_profile", "fvnsEncapBlk": "aci_ranges.translated_ranges", "infraAttEntityP": "aci_attachable_access_entity_profile.translated_attachable_access_entity_profile", "fvEPSelector": "aci_endpoint_security_group_selector.translated_endpoint_security_group_selector", "mcpInstPol": "aci_mcp_instance_policy.translated_mcp_instance_policy", "dhcpLbl": "aci_bd_dhcp_label.translated_bd_dhcp_label", "ipNexthopP": "aci_l3out_static_route_next_hop.translated_l3out_static_route_next_hop", "l3extIp": "aci_l3out_path_attachment_secondary_ip.translated_l3out_path_attachment_secondary_ip", "l3IfPol": "aci_l3_interface_policy.translated_l3_interface_policy", "maintMaintP": "aci_maintenance_policy.translated_maintenance_policy", "fvnsVsanInstP": "aci_vsan_pool.translated_vsan_pool", "firmwareFwP": "aci_firmware_policy.translated_firmware_policy", "cloudApp": "aci_cloud_applicationcontainer.translated_cloud_applicationcontainer", "fvRsDomAtt": "aci_epg_to_domain.translated_epg_to_domain", "fvRsProv": "aci_epg_to_contract.translated_epg_to_contract", "ospfExtP": "aci_l3out_ospf_external_policy.translated_l3out_ospf_external_policy", "bgpPeerPfxPol": "aci_bgp_peer_prefix.translated_bgp_peer_prefix", "infraSetPol": "aci_fabric_wide_settings.translated_fabric_wide_settings", "vnsAbsConnection": "aci_connection.translated_connection", "vmmVSwitchPolicyCont": "aci_vswitch_policy.translated_vswitch_policy", "maintMaintGrp": "aci_pod_maintenance_group.translated_pod_maintenance_group", "spanDestGrp": "aci_span_destination_group.translated_span_destination_group", "dhcpOptionPol": "aci_dhcp_option_policy.translated_dhcp_option_policy", "infraRsAccBaseGrp": "aci_access_group.translated_access_group", "fvRsCtxToBgpCtxAfPol": "aci_vrf_to_bgp_address_family_context.translated_vrf_to_bgp_address_family_context", "spanSpanLbl": "aci_span_sourcedestination_group_match_label.translated_span_sourcedestination_group_match_label", "vnsRedirectDest": "aci_destination_of_redirected_traffic.translated_destination_of_redirected_traffic", "aaaUserEp": "aci_global_security.translated_global_security", "aaaLoginDomain": "aci_login_domain.translated_login_domain", "aaaTacacsPlusProviderGroup": "aci_tacacs_provider_group.translated_tacacs_provider_group", "aaaLdapGroupMapRule": "aci_ldap_group_map_rule.translated_ldap_group_map_rule", "fvnsVxlanInstP": "aci_vxlan_pool.translated_vxlan_pool", "bgpProtP": "aci_l3out_bgp_protocol_profile.translated_l3out_bgp_protocol_profile", "aaaRadiusProviderGroup": "aci_radius_provider_group.translated_radius_provider_group", "fvAp": "aci_application_profile.translated_application_profile", "edrErrDisRecoverPol": "aci_error_disable_recovery.translated_error_disable_recovery", "cloudExtEPg": "aci_cloud_external_epg.translated_cloud_external_epg", "bgpBestPathCtrlPol": "aci_bgp_best_path_policy.translated_bgp_best_path_policy", "fvRsConsIf": "aci_epg_to_contract_interface.translated_epg_to_contract_interface", "tagTag": "aci_tag.translated_tag", "aaaUserRole": "aci_user_security_domain_role.translated_user_security_domain_role", "monEPGPol": "aci_monitoring_policy.translated_monitoring_policy", "bgpCtxPol": "aci_bgp_timers.translated_bgp_timers", "vzSubj": "aci_contract_subject.translated_contract_subject", "l3extVirtualLIfP": "aci_l3out_floating_svi.translated_l3out_floating_svi", "infraFexBndlGrp": "aci_fex_bundle_group.translated_fex_bundle_group", "hsrpGroupP": "aci_l3out_hsrp_interface_group.translated_l3out_hsrp_interface_group", "mgmtRsInBStNode": "aci_static_node_mgmt_address.translated_static_node_mgmt_address", "aaaRadiusProvider": "aci_radius_provider.translated_radius_provider", "l3extRsNodeL3OutAtt": "aci_logical_node_to_fabric_node.translated_logical_node_to_fabric_node", "ospfIfP": "aci_l3out_ospf_interface_profile.translated_l3out_ospf_interface_profile", "infraSpAccPortP": "aci_spine_interface_profile.translated_spine_interface_profile", "fvnsVlanInstP": "aci_vlan_pool.translated_vlan_pool", "stpIfPol": "aci_spanning_tree_interface_policy.translated_spanning_tree_interface_policy", "coopPol": "aci_coop_policy.translated_coop_policy", "cloudEPg": "aci_cloud_epg.translated_cloud_epg", "l2extDomP": "aci_l2_domain.translated_l2_domain", "aaaLdapGroupMapRuleRef": "aci_ldap_group_map_rule_to_group_map.translated_ldap_group_map_rule_to_group_map", "vzBrCP": "aci_contract.translated_contract", "vzCPIf": "aci_imported_contract.translated_imported_contract", "infraBrkoutPortGrp": "aci_leaf_breakout_port_group.translated_leaf_breakout_port_group", "infraGeneric": "aci_access_generic.translated_access_generic", "vzAny": "aci_any.translated_any", "aaaLdapProvider": "aci_ldap_provider.translated_ldap_provider", "ospfRtSummPol": "aci_ospf_route_summarization.translated_ospf_route_summarization", "hsrpIfPol": "aci_hsrp_interface_policy.translated_hsrp_interface_policy", "bgpExtP": "aci_l3out_bgp_external_policy.translated_l3out_bgp_external_policy", "aaaUserCert": "aci_x509_certificate.translated_x509_certificate", "l2extOut": "aci_l2_outside.translated_l2_outside", "cloudRouterP": "aci_cloud_vpn_gateway.translated_cloud_vpn_gateway", "rtctrlSetAddComm": "aci_action_rule_additional_communities.translated_action_rule_additional_communities", "ipRouteP": "aci_l3out_static_route.translated_l3out_static_route", "hsrpGroupPol": "aci_hsrp_group_policy.translated_hsrp_group_policy", "bgpPeerP": "aci_bgp_peer_connectivity_profile.translated_bgp_peer_connectivity_profile", "rtctrlMatchCommRegexTerm": "aci_match_regex_community_terms.translated_match_regex_community_terms", "cloudAwsProvider": "aci_cloud_aws_provider.translated_cloud_aws_provider"}

dn_list = []
query_strings = {}
query_dns = []
sources = []

class FilterModule(object):
    def filters(self):
        return {
            "get_rest_paths": self.get_rest_paths,
            "get_dns": self.get_dns,
            "get_resources_and_dns": self.get_resources_and_dns,
            "get_factual_dns_rest": self.get_factual_dns_rest,
            "get_qs_source_from_names": self.get_qs_source_from_names,
            "get_qs_source_from_path": self.get_qs_source_from_path,
            "get_dns_from_imdata": self.get_dns_from_imdata,
            "calculate_dn": self.calculate_dn,
            "warn_import": self.warn_import,
        }

    def warn_import(self, message):
        ansi_escape_regex = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        Display().warning([ansi_escape_regex.sub('', msg) for msg in message])

    def remove_ip_from_url(self, url):
        pattern = r"(?:https?://)?\b(?:\d{1,3}\.){3}\d{1,3}\b"
        updated_url = re.sub(pattern, "", url)
        return updated_url.replace(".json", "")

    # def get_rest_query_string(self, registered_tasks):
    #     for key, value in registered_tasks.items():
    #         if isinstance(value, dict):
    #             if value.get("attributes").get("dn") is None:
    #                 query_strings.update({"/api/class/{0}.json?query-target-filter=eq({1}.name,"{2}")".format(key, key, value.get("attributes").get("name")):value.get("attributes").get("name")})
    #             else:
    #                 terraform_resource = CLASS_MAP.get(key, "")
    #                 temp = {terraform_resource:value.get("attributes").get("dn")}
    #                 query_strings.update({json.dumps(temp):"is_DN"})
    #             if value.get("children") is not None:
    #                 self.get_rest_query_string(value.get("children")[0])
    #     query_strings.update({self.remove_ip_from_url(str(registered_tasks.get("path_url"))):"is_URL"})
    #     return [query_strings]

    def get_factual_dns_rest(self, registered_tasks):
        for key, value in registered_tasks.items():
            if isinstance(value, dict):
                terraform_resource = CLASS_MAP.get(key, "")
                DN = value.get("attributes").get("dn")
                if terraform_resource != "" and DN is not None:
                    name_of_resource = value.get("attributes").get("name") if value.get("attributes").get("name") not in (None, "") else DN.replace("/", "_").replace("[", "_").replace("]", "_").replace(".", "_")
                    temp = {terraform_resource + str("_" + name_of_resource): DN}
                    query_strings.update({json.dumps(temp):"is_DN"})
                elif terraform_resource == "" and DN is not None:
                    temp = {"aci_rest_managed.translated_{0}".format(key): key+":"+DN}
                    query_strings.update({json.dumps(temp):"is_DN"})
                if value.get("children") is not None:
                    self.get_factual_dns_rest(value.get("children")[0])
        return [query_strings]

    def get_qs_source_from_names(self, registered_tasks, source=""):
        for key, value in registered_tasks.items():
            if isinstance(value, dict):
                source += "/" + str(value.get("attributes").get("name")) + str(value.get("attributes").get("dn"))
                if value.get("attributes").get("dn") is None:
                    query_strings.update({'/api/class/{0}.json?query-target-filter=eq({1}.name,"{2}")'.format(key, key, value.get("attributes").get("name")):"from_name"})
                    query_strings.update({source:"is_source"})
                if value.get("children") is not None:
                    self.get_qs_source_from_names(value.get("children")[0], source)
        return [query_strings]

    def get_qs_source_from_path(self, registered_tasks):
        for key, value in registered_tasks.items():
            if isinstance(value, dict):
                if value.get("attributes").get("dn") is None:
                    query_strings.update({'/api/class/{0}.json?query-target-filter=eq({1}.name,"{2}")'.format(key, key, value.get("attributes").get("name")):"from_path"})
                if value.get("children") is not None:
                    self.get_qs_source_from_path(value.get("children")[0])
        query_strings.update({self.remove_ip_from_url(str(registered_tasks.get("path_url"))):"is_source"})
        return [query_strings]

    def get_dns_from_imdata(self, registered_tasks):
        obj = ""
        for data in registered_tasks:
            for i in data:
                obj = i
            terraform_resource = CLASS_MAP.get(obj, "")
            DN = data.get(obj).get("attributes").get("dn")
            if terraform_resource != "" and DN is not None:
                name_of_resource = data.get(obj).get("attributes").get("name") if data.get(obj).get("attributes").get("name") not in (None, "") else DN.replace("/", "_").replace("[", "_").replace("]", "_").replace(".", "_")
                query_dns.append(json.dumps({terraform_resource + str("_" + name_of_resource): DN}))
            elif terraform_resource == "" and DN is not None:
                query_dns.append(json.dumps({"aci_rest_managed.translated_{0}".format(obj): obj+":"+DN}))
        return query_dns
    
    def calculate_dn(self, provisional_dn, sources):
        get_provisional_dn = json.loads(provisional_dn)
        get_val = list(get_provisional_dn.values())[0]
        pattern = r"(?<!\[)-([^/\[\]]+)|-(\w+)\Z|\[([^]]+)\]"
        matches = re.findall(pattern, get_val)
        sub_dns = []
        for match in matches:
            if match[0]:
                sub_dns.append(match[0])
            elif match[1]:
                sub_dns.append(match[1])
            elif match[2]:
                sub_dns.append(match[2])
        print("sub_dns {0}".format(sub_dns))
        print("sources {0}".format(sources))
        for source in sources:
            found = False
            for sub_dn in sub_dns:
                if sub_dn in source:
                    found = True
                else:
                    found = False
                    break
            if found:
                return [json.dumps(get_provisional_dn)]
        if not found:
            return [""]

    def get_rest_paths(self, registered_tasks):
        clss = ""
        for i in registered_tasks:
            clss = i
        if registered_tasks.get(clss).get("attributes").get("dn") is None:
            return '/api/class/{0}.json?query-target-filter=eq({1}.name,"{2}")'.format(clss, clss, registered_tasks[clss]["attributes"]["name"])
        else:
            return "None"

    def get_dns(self, registered_dn):
        obj = ""
        for i in registered_dn:
            obj = i
        terraform_resource = CLASS_MAP.get(obj, "")
        DN = registered_dn.get(obj).get("attributes").get("dn")
        if terraform_resource != "" and DN is not None:
            name_of_resource = registered_dn.get(obj).get("attributes").get("name") if registered_dn.get(obj).get("attributes").get("name") not in (None, "") else DN.replace("/", "_").replace("[", "_").replace("]", "_").replace(".", "_")
            return [json.dumps({terraform_resource + str("_" + name_of_resource): DN})]
        elif terraform_resource == "" and DN is not None:
            return [json.dumps({"aci_rest_managed.translated_{0}".format(obj): obj+":"+DN})]
        elif DN is None:
            return [json.dumps({"": ""})]

    def get_resources_and_dns(self, dns):
        non_existent_classes = {}
        import_dict = {}
        resource_counts = {}
        for dn in dns:
            if dn != "":
                dn_dict = json.loads(dn)
                resource = list(dn_dict.keys())[0]
                resource_dn = list(dn_dict.values())[0]
                if resource != "":
                    if resource in resource_counts:
                        resource_counts[resource] += 1
                        resource += str(resource_counts[resource])
                    else:
                        resource_counts[resource] = 1
                    import_dict.update({resource_dn: resource})
                if "aci_rest_managed.translated_" in resource:
                    non_existent_classes.update({resource : resource_dn})
        if len(non_existent_classes) != 0:
            Display().warning("Resources for {0} don't exist in Terraform. These will be translated to aci rest managed resources {1} in the Terraform configuration file instead.".format(list(non_existent_classes.values()), list(non_existent_classes.keys())))
        return import_dict
