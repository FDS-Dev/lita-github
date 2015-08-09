# -*- coding: UTF-8 -*-
#
# Copyright 2014 PagerDuty, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'lita-github/r'
require 'lita-github/general'
require 'lita-github/config'
require 'lita-github/octo'
require 'lita-github/org'
require 'lita-github/filters'

module Lita
  # Lita Handler
  module Handlers
    # GitHub Lita Handler
    class GithubOrg < Handler
      include LitaGithub::General # Github handler common-use methods
      include LitaGithub::Config  # Github handler Lita configuration methods
      include LitaGithub::Octo    # Github handler common-use Octokit methods
      include LitaGithub::Org     # Github handler common-use Organization methods
      include LitaGithub::Filters # Github handler common-use method filters

      on :loaded, :setup_octo # from LitaGithub::Octo

      KNOWN_PERMS = %w(pull push admin)

      route(
        /#{LitaGithub::R::A_REG}(?:teams|org\s+?teams|org\s+?team\s+?list)(?<org>\s+[a-zA-Z0-9_\-]+)?/,
        :org_teams_list,
        command: true,
        help: {
          'gh org teams [organization]' => 'show all teams of an organization',
          'gh teams [organization]' => 'an alias for gh org teams'
        }
      )

      # rubocop:disable Metrics/LineLength
      route(
        # /#{LitaGithub::R::A_REG}org\s+?team\s+?add(?<org>\s+?[a-zA-Z0-9_\-]+)?(?<perm>\s+?[a-zA-Z]+)\s+?(?<name>.*)$/,
        /#{LitaGithub::R::A_REG}org\s+?team\s+?add(?<org>\s+?[a-zA-Z0-9_\-]+)?/,
        command: true,
        confirmation: true,
        help: {
          'gh org team add PagerDuty name:"All Employees" perms:pull' => 'add an "All Engineers" team with pull permissions',
          'gh org team add PagerDuty name:Leads perms:pull' => 'add a "Leads" team with admin permissions',
          'gh org team add PagerDuty name:Ops perms:push' => 'add an "Ops" team with push permissions'
        }
      ) do |resp|
        if auth.user_in_group?(resp.user, :admin)
          org_team_add(resp)
        else
          resp.reply('You are not authorized to perform this action')
        end
      end
      # rubocop:enable Metrics/LineLength

      route(
        /#{LitaGithub::R::A_REG}org\s+?team\s+?rm(?<org>\s+?[a-zA-Z0-9_\-]+)?(?<team>\s+?[a-zA-Z0-9_\-]+)/,
        command: true,
        confirmation: true,
        help: {
          'gh org team rm PagerDuty ops' => 'delete the Operations team',
          'gh org team rm PagerDuty 42' => 'delete the team with id 42'
        }
      ) do |resp|
        if auth.user_in_group?(resp.user, :admin)
          org_team_rm(resp)
        else
          resp.reply('You are not authorized to perform this action')
        end
      end

      # rubocop:disable Metrics/LineLength
      route(
        /#{LitaGithub::R::A_REG}org\s+?user\s+?add(?<org>\s+?[a-zA-Z0-9_\-]+)?(?<team>\s?[a-zA-Z0-9_\-]+)\s+?(?<username>[a-zA-Z0-9_\-]+)/,
        command: true,
        confirmation: { allow_self: false },
        help: {
          'gh org user add PagerDuty everyone theckman' => 'add the user theckman to the PagerDuty/everyone team -- this requires confirmation from another user. NOTE: This will add the member to the organization if they are not already!!',
          'gh org user add PagerDuty 42 theckman' => "same as above, except with the team's ID instead of the slug"
        }
      ) do |resp|
        if auth.user_in_group?(resp.user, :admin)
          org_user_add(resp)
        else
          resp.reply('You are not authorized to perform this action')
        end
      end

      route(
        /#{LitaGithub::R::A_REG}org\s+?user\s+?rm(?<org>\s+?[a-zA-Z0-9_\-]+)?(?<team>\s?[a-zA-Z0-9_\-]+)\s+?(?<username>[a-zA-Z0-9_\-]+)/,
        comamnd: true,
        confirmation: { allow_self: false },
        help: {
          'gh org team rm PagerDuty everyone theckman' => 'remove the user theckman from the PagerDuty/everyone team, if this is their last team will remove them from the org. Requires confirmation from another user.',
          'gh org team rm PagerDuty 42 theckman' => "same as above, except with the team's ID instead of the slug"
        }
      ) do |resp|
        if auth.user_in_group?(resp.user, :admin)
          org_user_rm(resp)
        else
          resp.reply('You are not authorized to perform this action')
        end
      end
      # rubocop:enable Metrics/LineLength

      route(
        /#{LitaGithub::R::A_REG}org\s+?eject(?<org>\s+?[a-zA-Z0-9_\-]+)?(?<username>\s+?[a-zA-Z0-9_\-]+)/,
        command: true,
        confirmation: { allow_self: false },
        help: {
          'gh org eject PagerDuty theckman' => 'forcibly removes the user from all groups in the organization -- ' \
                                               'this is meant for someone leaving the organization. Requires ' \
                                               'confirmation from another user.'
        }
      ) do |resp|
        if auth.user_in_group?(resp.user, :admin)
          org_eject_user(resp)
        else
          resp.reply('You are not authorized to perform this action')
        end
      end

      def org_teams_list(response)
        md = response.match_data
        org = md[:org].nil? ? config.default_org : organization(md[:org].strip)

        begin
          teams = octo.organization_teams(org)
        rescue Octokit::NotFound
          return response.reply(t('org_not_found', org: org))
        end

        tl = teams.length

        o = teams.shift

        reply = t('org_teams_list.header', org: org, num_teams: tl)
        reply << t('org_teams_list.team', o.to_h)

        sort_by_name(teams).each { |team| reply << t('org_teams_list.team', team.to_h) }

        response.reply(reply)
      end

      def org_team_add(response)
        return response.reply(t('method_disabled')) if func_disabled?(__method__)

        opts = opts_parse(response.message.body)
        vo = validate_team_add_opts(opts)
        return response.reply(vo[:msg]) unless vo[:success]

        md = response.match_data
        org, perm, name = [organization(md['org'].strip), opts[:perms].strip.downcase, opts[:name]]

        return response.reply(
          t('org_team_add.perm_not_permitted', perms: config.org_team_add_allowed_perms.join(', '))
        ) unless permission_allowed?(perm)

        begin
          resp = octo.create_team(org, name: name, permission: perm)
        rescue Octokit::NotFound
          return response.reply(t('org_not_found', org: org))
        end

        response.reply(t('org_team_add.created_team', resp.to_h))
      end

      def org_team_rm(response)
        return response.reply(t('method_disabled')) if func_disabled?(__method__)

        md = response.match_data
        org, team = [organization(md['org'].strip), md['team'].strip]

        t_id = team_id(team, org)
        t = team?(t_id)

        return response.reply(t('team_not_found', team: team)) unless t

        if octo.delete_team(t_id)
          response.reply(t('org_team_rm.pass', t.to_h))
        else
          response.reply(t('org_team_rm.fail', t.to_h))
        end
      end

      # rubocop:disable Metrics/CyclomaticComplexity
      # rubocop:disable Metrics/PerceivedComplexity
      def org_user_add(response)
        return response.reply(t('method_disabled')) if func_disabled?(__method__)

        md = response.match_data
        org, team, username = [organization(md['org'].strip), md['team'].strip, md['username']]

        begin
          user_id = octo.user(username)[:id]
        rescue Octokit::NotFound
          return response.reply(t('user_not_found', n: username))
        end

        return response.reply(t('nope')) if octo.user[:id] == user_id

        begin
          team_obj = octo.team(team_id(team, org))
        rescue Octokit::NotFound
          return response.reply(t('team_not_found', team: team))
        end

        begin
          resp = octo.add_team_membership(team_obj[:id], username)
        rescue StandardError => e
          return response.reply(t('boom', m: e.message))
        end

        if resp
          response.reply(t('org_user_add.added', u: username, o: org, t: team_obj[:name], s: team_obj[:slug]))
        else
          response.reply(t('org_user_add.failed', t: team_obj[:name]))
        end
      end

      def org_user_rm(response)
        return response.reply(t('method_disabled')) if func_disabled?(__method__)
        md = response.match_data
        org, team, username = [organization(md['org'].strip), md['team'].strip, md['username']]

        begin
          user_id = octo.user(username)[:id]
        rescue Octokit::NotFound
          return response.reply(t('user_not_found', n: username))
        end

        return response.reply(t('nope')) if octo.user[:id] == user_id

        begin
          team = octo.team(team_id(team, org))
        rescue Octokit::NotFound
          return response.reply(t('team_not_found', team: team))
        end

        begin
          resp = octo.remove_team_member(team[:id], username)
        rescue StandardError => e
          return response.reply(t('boom', m: e.message))
        end

        if resp
          response.reply(t('org_user_rm.removed', u: username, o: org, t: team[:name], s: team[:slug]))
        else
          response.reply(t('org_user_rm.failed', t: team[:name]))
        end
      end
      # rubocop:enable Metrics/CyclomaticComplexity
      # rubocop:enable Metrics/PerceivedComplexity

      def org_eject_user(response)
        return response.reply(t('method_disabled')) if func_disabled?(__method__)
        md = response.match_data
        org, username = [organization(md['org'].strip), md['username'].strip]

        begin
          user_id = octo.user(username)[:id]
        rescue Octokit::NotFound
          return response.reply(t('user_not_found', n: username))
        end

        return response.reply(t('nope')) if octo.user[:id] == user_id

        begin
          resp = octo.remove_organization_member(org, username)
        rescue StandardError => e
          return response.reply(t('boom', m: e.message))
        end

        if resp
          response.reply(t('org_eject_user.ejected', user: username, org: org))
        else
          response.reply(t('org_eject_user.failed'))
        end
      end

      private

      def validate_team_add_opts(opts)
        h = { success: true, msg: '' }
        h[:msg] << t('org_team_add.missing_option', opt: 'name') unless opts.key?(:name)
        h[:msg] << t('org_team_add.missing_option', opt: 'perms') unless opts.key?(:perms)
        h[:msg] << t('org_team_add.perm_invalid') if opts.key?(:perms) && !KNOWN_PERMS.include?(opts[:perms].downcase)
        h[:success] = false unless h[:msg].empty?
        h
      end

      def permission_allowed?(perm)
        config.org_team_add_allowed_perms.include?(perm)
      end
    end

    Lita.register_handler(GithubOrg)
  end
end
