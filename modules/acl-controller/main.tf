# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

resource "aws_ecs_service" "this" {
  name            = "consul-acl-controller"
  cluster         = var.ecs_cluster_arn
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = 1

  network_configuration {
    subnets          = var.subnets
    security_groups  = var.security_groups
    assign_public_ip = var.assign_public_ip
  }

  enable_execute_command = true

  launch_type = var.use_capacity_provider ? null : var.launch_type

  dynamic "capacity_provider_strategy" {
    for_each = var.use_capacity_provider ? [var.capacity_provider] : []

    content {
      capacity_provider = capacity_provider_strategy.value
      weight = 100
    }
  }

  dynamic "deployment_circuit_breaker" {
    for_each = var.deployment_circuit_breaker[*]

    content {
      enable = deployment_circuit_breaker.value.enable
      rollback = deployment_circuit_breaker.value.rollback
    }
  }

  dynamic "deployment_controller" {
    for_each = var.deployment_controller_type[*]

    content {
      type = deployment_controller.value
    }
  }
}

resource "aws_ecs_task_definition" "this" {
  family                   = "${var.name_prefix}-consul-acl-controller"
  requires_compatibilities = var.requires_compatibilities
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  task_role_arn            = aws_iam_role.this_task.arn
  execution_role_arn       = aws_iam_role.this_execution.arn
  container_definitions = jsonencode([
    {
      name             = "consul-acl-controller"
      image            = var.consul_ecs_image
      essential        = true
      logConfiguration = var.log_configuration,
      command = concat(
        [
          "acl-controller", "-iam-role-path", var.iam_role_path,
        ],
        var.consul_partitions_enabled ? [
          "-partitions-enabled",
          "-partition", var.consul_partition
        ] : [],
      )
      linuxParameters = {
        initProcessEnabled = true
      }
      secrets = concat([
        {
          name      = "CONSUL_HTTP_TOKEN",
          valueFrom = var.consul_bootstrap_token_secret_arn
        }],
        var.consul_server_ca_cert_arn != "" ? [
          {
            name      = "CONSUL_CACERT_PEM",
            valueFrom = var.consul_server_ca_cert_arn
          }
      ] : [])
      environment = [
        {
          name  = "CONSUL_HTTP_ADDR"
          value = var.consul_server_http_addr
        }
      ]
      readonlyRootFilesystem = true
    },
  ])
}

resource "aws_iam_role" "this_task" {
  name = "${var.name_prefix}-consul-acl-controller-task"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      },
    ]
  })

  inline_policy {
    name = "exec"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect = "Allow"
          Action = [
            "ssmmessages:CreateControlChannel",
            "ssmmessages:CreateDataChannel",
            "ssmmessages:OpenControlChannel",
            "ssmmessages:OpenDataChannel",

            "ecs:ListTasks",
            "ecs:DescribeTasks",
          ]
          Resource = "*"
        },
      ]
    })
  }
}

resource "aws_iam_policy" "this_execution" {
  name        = "${var.name_prefix}-consul-acl-controller-execution"
  path        = "/ecs/"
  description = "Consul controller execution"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "secretsmanager:GetSecretValue",
          "kms:Decrypt",
        ],
        Resource = compact([
          var.consul_bootstrap_token_secret_arn,
          var.consul_server_ca_cert_arn,
          var.secret_kms_key_arn,
        ])
      },
    ]
  })
}

resource "aws_iam_role" "this_execution" {
  name = "${var.name_prefix}-consul-acl-controller-execution"
  path = "/ecs/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "consul-controller-execution" {
  role       = aws_iam_role.this_execution.id
  policy_arn = aws_iam_policy.this_execution.arn
}

resource "aws_iam_role_policy_attachment" "additional_execution_policies" {
  count      = length(var.additional_execution_role_policies)
  role       = aws_iam_role.this_execution.id
  policy_arn = var.additional_execution_role_policies[count.index]
}

data "aws_iam_policy" "ecs_execution_policy" {
  arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy_attachment" "attach_ecs_execution_policy" {
  role       = aws_iam_role.this_execution.id
  policy_arn = data.aws_iam_policy.ecs_execution_policy.arn
}
