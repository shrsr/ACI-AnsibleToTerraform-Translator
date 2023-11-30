# ACI-AnsibleToTerraform-Translator
This repository showcases a tool for transitioning Ansible configurations for Application Centric Infrastructure (ACI) into Terraform configuration files. It is designed to simplify the migration process from Ansible to Terraform in managing ACI. Please note, while it strives to be comprehensive, this tool primarily serves as a learning resource and stepping stone, rather than a fully-fledged, enterprise-level solution.

Important Note
==============

* This translation process is specifically designed for **Application Centric Infrastructure (ACI)**.

* It's important to note that this is **not a static translation**.

* The process does not directly convert an Ansible playbook (written in YAML - YAML Ain't Markup Language) into a Terraform configuration file (written in HCL - HashiCorp Configuration Language).

* For the translation to complete, the selected playbook will be run by Ansible and will interact with the provided Application Policy Infrastructure Controller (APIC). After this, Terraform will import the configuration that has been applied.

* At a minimum, this process requires an APIC simulator.
