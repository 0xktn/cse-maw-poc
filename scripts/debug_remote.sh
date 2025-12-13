#!/bin/bash
INSTANCE_ID=$(aws ec2 describe-instances --filters "Name=tag:Name,Values=nitro-enclave-poc" "Name=instance-state-name,Values=running" --query "Reservations[0].Instances[0].InstanceId" --output text)
echo "Debugging Instance: $INSTANCE_ID"

CMDS='["cd /home/ec2-user/confidential-multi-agent-workflow", "echo --- ATTESTATION LOG HEAD ---", "head -c 2000 attestation.log", "echo", "echo --- ATTESTATION LOG TAIL ---", "tail -c 2000 attestation.log", "echo --- GREP ATTESTATION ---", "grep -a Attestation attestation.log || true", "echo --- GREP PLAINTEXT ---", "grep -a PLAINTEXT attestation.log || true"]'

CMD_ID=$(aws ssm send-command --region ap-southeast-1 --instance-ids $INSTANCE_ID --document-name "AWS-RunShellScript" --parameters commands="$CMDS" --query "Command.CommandId" --output text)

echo "Sent command: $CMD_ID"
echo "Waiting for output..."
sleep 2

while true; do
  STATUS=$(aws ssm list-command-invocations --region ap-southeast-1 --command-id "$CMD_ID" --details --query "CommandInvocations[0].Status" --output text)
  if [[ "$STATUS" == "Success" || "$STATUS" == "Failed" ]]; then
     echo "Status: $STATUS"
     aws ssm list-command-invocations --region ap-southeast-1 --command-id "$CMD_ID" --details --query "CommandInvocations[0].CommandPlugins[0].Output" --output text
     break
  fi
  echo -n "."
  sleep 2
done
