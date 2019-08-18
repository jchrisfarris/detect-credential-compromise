


ifndef BUCKET
$(error BUCKET is not set)
endif


ifndef version
	export version := $(shell date +%Y%b%d-%H%M)
endif

# Specific to this stack
export STACK_NAME=detect-credential-compromise
# Filename for the CFT to deploy
export STACK_TEMPLATE=CredentialCompromiseDetection-SAM-Template.yaml
# Name of the Zip file with all the function code and dependencies
export LAMBDA_PACKAGE=lambda-package.zip

# Application Variables
export AUTHOR=Chris Farris
export DESCRIPTION=Detect Credential Compromise
export GITHUB=https://github.com/jchrisfarris/detect-credential-compromise
export HOMEPAGE=https://www.chrisfarris.com/
export LICENSE=Apache-2.0


.PHONY: $(FUNCTIONS)

# Run all tests
test: cfn-validate
	cd lambda && $(MAKE) test

clean:
	cd lambda && $(MAKE) clean

#
# SAM Targets
#
package:
	cd lambda && $(MAKE) package

zipfile:
	cd lambda && $(MAKE) zipfile

template: package
	aws cloudformation package --template $(STACK_TEMPLATE) --s3-bucket $(BUCKET) --output-template-file $(STACK_NAME).output.yaml

create:
	aws serverlessrepo create-application \
	--author "$(AUTHOR)" \
	--description "$(DESCRIPTION)" \
	--name $(STACK_NAME) \
	--spdx-license-id $(LICENSE) \
	--readme-body file://SAM-README.md \
	--home-page-url $(HOMEPAGE) \
	--license-body file://LICENSE


release: package template
	$(eval app_arn := $(shell aws serverlessrepo list-applications | jq -r '.Applications[]  | select(.Name == "$(STACK_NAME)") | .ApplicationId'))
	aws serverlessrepo create-application-version \
	--application-id $(app_arn) \
	--semantic-version $(version) \
	--source-code-url $(GITHUB) \
	--template-body file://$(STACK_NAME).output.yaml




# # # Update the Lambda Code without modifying the CF Stack
# update: package $(FUNCTIONS)
# 	for f in $(FUNCTIONS) ; do \
# 	  aws lambda update-function-code --function-name $$f --zip-file fileb://lambda/$(LAMBDA_PACKAGE) ; \
# 	done

# # Update one specific function. Called as "make fupdate function=<fillinstackprefix>-aws-inventory-ecs-inventory"
# fupdate: zipfile
# 	aws lambda update-function-code --function-name $(function) --zip-file fileb://lambda/$(LAMBDA_PACKAGE) ; \

