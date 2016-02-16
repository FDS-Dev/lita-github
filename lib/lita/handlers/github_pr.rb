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
require 'lita-github/config'
require 'lita-github/octo'
require 'lita-github/org'
require 'lita-github/repo'
require 'lita-github/filters'
require 'lita-github/auth'
require 'json'

module Lita
  # Lita handler
  module Handlers
    # Handler class for GitHub PR management
    class GithubPR < Handler
      include LitaGithub::R       # Github handler common-use regex constants
      include LitaGithub::Config  # Github handler Lita configuration methods
      include LitaGithub::Octo    # Github handler common-use Octokit methods
      include LitaGithub::Org     # Github handler common-use Organization methods
      include LitaGithub::Repo    # Github handler common-use Repository methods
      include LitaGithub::Filters # Github handler common-use method filters
      include LitaGithub::Auth    # Github handler common-use Auth methods

      on :loaded, :setup_octo # from LitaGithub::Octo

      class << self
        attr_accessor :pr_state
      end

      def self.default_config(config)
        self.pr_state = {}
      end

      route(
        /pr\s+?info\s+?#{LitaGithub::R::REPO_REGEX}\s+?#?(?<pr>\d+?)$/,
        :pr_info,
        command: true,
        help: { 'pr info lita-github 42' => 'show some information about the pull request' }
      )

      route(
        /(?:pr assign)\s+?#{LitaGithub::R::REPO_REGEX}\s+?#?(?<pr>\d+?)\s+?(?<user>[[:graph:]]+?)$/,
        :pr_assign,
        command: true,
        help: { 'pr assign lita-github 42 adnichols' => 'Assign a PR to someone' }
      )

      route(
        /(?:pr check)\s+?#{LitaGithub::R::REPO_REGEX}\s+?#?(?<pr>\d+?)$/,
        :pr_check,
        command: true,
        help: { 'pr check lita-github 42' => 'Check if a PR is ok to merge' }
      )

      route(
        /(?:pr inspect)\s+?#{LitaGithub::R::REPO_REGEX}\s+?#?(?<pr>\d+?)$/,
        :pr_inspect,
        command: true,
        help: { 'pr inspect lita-github 42' => 'view all PR attributes' }
      )

      route(
        /(?:pr comments)\s+?#{LitaGithub::R::REPO_REGEX}\s+?#?(?<pr>\d+?)$/,
        :pr_comments,
        command: true,
        help: { 'pr comments lita-github 42' => 'view all PR comments' }
      )

      route(
        /(?:pr lockdown)\s+?(?<command>[[:graph:]]+?)$/,
        :pr_lockdown,
        commands: true,
        help: {
          'pr lockdown [enable|disable|status]' => 'When locked, limit merging to admins'
        }
      )

      route(
        /(?:pr unassign)\s+?#{LitaGithub::R::REPO_REGEX}\s+?#?(?<pr>\d+?)$/,
        :pr_unassign,
        command: true,
        help: { 'pr unassign lita-github 42' => 'Unassign a PR' }
      )

      route(
        /(?:pr merge)\s+?#{LitaGithub::R::REPO_REGEX}\s+?#?(?<pr>\d+?)$/,
        :pr_merge,
        command: true,
        confirmation: true,
        help: {
          'pr merge lita-github 42' => 'ship it!'
        }
      )

      route(
        /pr\s+?list\s+?#{LitaGithub::R::REPO_REGEX}/, :pr_list,
        command: true,
        help: {
          'pr list PagerDuty/lita-github' => 'list the 10 oldest and newest PRs'
        }
      )

      def pr_assign(response)
        org, repo, pr, user = pr_assign_match(response.match_data)
        full_name = rpo(org, repo)

        pr_h = pull_request(full_name, pr)
        return response.reply(t('not_found', pr: pr, org: org, repo: repo)) if pr_h[:fail] && pr_h[:not_found]

        begin
          updated_pr = octo.update_issue(full_name, pr, :assignee => user)
        rescue
          response.reply("Failed to assign #{pr} to #{user} #{pr_h[:pr][:html_url]}")
          return false
        end

        if updated_pr[:assignee][:login] == user
          response.reply("PR #{pr} assigned to #{user} #{pr_h[:pr][:html_url]}")
        else
          response.reply("Failed to assign #{pr} to #{user} #{pr_h[:pr][:html_url]}")
        end
      end

      def pr_lockdown(response)
        command = response.match_data['command']
        case command
        when 'status'
          state = lockdown_status(response)
          if state[:state] == "enabled"
            response.reply("Lockdown is ENABLED by #{state[:enabled_by]}")
          else
            response.reply("Lockdown is DISABLED by #{state[:disabled_by]}")
          end

        when 'enable'
          if lockdown_enable(response)
            response.reply("Lockdown enabled")
          else
            response.reply("Failed to enable lockdown")
          end

        when 'disable'
          if lockdown_disable(response)
            response.reply("Lockdown disabled")
          else
            response.reply("Failed to disable lockdown")
          end

        else
          response.reply("Unknown lockdown command #{command}")
        end
      end

      def lockdown_status(response)
        s = {}
        s[:state] = redis.get("lockdown:state")
        s[:enabled_by] = redis.get("lockdown:enabled_by")
        s[:disabled_by] = redis.get("lockdown:disabled_by")
        return s
      end

      def lockdown_enable(response)
        return false unless permit_user?(__method__, response)
        redis.set("lockdown:state", "enabled")
        redis.del("lockdown:disabled_by")
        redis.set("lockdown:enabled_by", response.user.name)
        if redis.get("lockdown:state") == "enabled"
          return true
        else
          return false
        end
      end

      def lockdown_disable(response)
        return false unless permit_user?(__method__, response)
        redis.set("lockdown:state", "disabled")
        redis.del("lockdown:enabled_by")
        redis.set("lockdown:disabled_by", response.user.name)
        if redis.get("lockdown:state") == "disabled"
          return true
        else
          return false
        end
      end

      def pr_unassign(response)
        org, repo, pr = pr_match(response.match_data)
        full_name = rpo(org, repo)

        pr_h = pull_request(full_name, pr)
        return response.reply(t('not_found', pr: pr, org: org, repo: repo)) if pr_h[:fail] && pr_h[:not_found]

        begin
          updated_pr = octo.update_issue(full_name, pr, :assignee => nil)
        rescue
          response.reply("Failed to unassign #{pr} (R)")
          return false
        end

        if updated_pr[:assignee] == nil
          response.reply("PR #{pr} unassigned #{pr_h[:pr][:html_url]}")
        else
          response.reply("Failed to unassign #{pr} #{pr_h[:pr][:html_url]}")
        end
      end

      # rubocop:disable Metrics/CyclomaticComplexity
      # rubocop:disable Metrics/PerceivedComplexity
      def pr_info(response)
        org, repo, pr = pr_match(response.match_data)
        full_name = rpo(org, repo)

        pr_h = pull_request(full_name, pr)
        return response.reply(t('not_found', pr: pr, org: org, repo: repo)) if pr_h[:fail] && pr_h[:not_found]

        info = build_pr_info(pr_h[:pr], full_name)
        comparison_url = "https://github.com/#{full_name}/compare/#{info[:base_sha]}...#{info[:pr_sha]}"
        info.merge!(repo: full_name, compare: comparison_url)

        reply = t('pr_info.header', info) << t('pr_info.status', info)
        reply << (info[:state] == :merged ? t('pr_info.merged', info) : t('pr_info.mergeable', info))
        reply << t('pr_info.commit_info', info) << t('pr_info.comments', info)

        response.reply(reply)
      end

      def pr_check(response)
        org, repo, pr = pr_match(response.match_data)
        full_name = rpo(org, repo)

        pr_h = pull_request(full_name, pr)
        return response.reply(t('not_found', pr: pr, org: org, repo: repo)) if pr_h[:fail] && pr_h[:not_found]

        pr_get_state(response, pr_h)
        pr_show_state(response)
      end

      def pr_get_state(response, pr_h)
        # Init this
        pr_state_init(pr_h)

        # Gather all our results
        pr_test_pass!(response, pr_h)
        pr_review_pass!(response, pr_h)
        jenkins_checks_pass!
      end

      def pr_pre_merge_pass?(response, pr_h)
        # Get our state
        pr_get_state(response, pr_h)
        p = self.class.pr_state
        unless p[:test]
          return false
        end

        unless p[:review]
          return false
        end

        unless p[:jenkins]
          return false
        end

        unless p[:jenkins_lst]
          return false
        end
        true
      end

      def pr_show_state(response)
        p = self.class.pr_state
        r = "PR #{p[:id]} Passed CI: #{p[:test]}"
        r << " | Reviewed: #{p[:review]} by #{p[:reviewer]}"
        r << " | long_system_test passing: #{p[:jenkins_lst]}"
        if p[:jenkins_lst] == false
          r << " ("
          p[:lst_jobs].each do |name, result|
            r << "#{result}"
          end
          r << ")"
        end
        r << " | master open for merge: #{p[:jenkins]}"
        if p[:jenkins] == false
          r << " ("
          p[:jobs].each do |name, result|
            r << "#{result}"
          end
          r << ")"
        end
        r << " | #{p[:url]} | Already merged? #{p[:merged]}"
        response.reply(r)
      end

      def pr_state_init(pr_h)
        self.class.pr_state = {}
        self.class.pr_state[:id] = pr_h[:pr][:number]
        self.class.pr_state[:url] = pr_h[:pr][:html_url]
        self.class.pr_state[:merged] = pr_h[:pr][:merged]
      end

      def pr_inspect(response)
        return false unless permit_user?(__method__, response)
        org, repo, pr = pr_match(response.match_data)
        full_name = rpo(org, repo)

        pr_h = pull_request(full_name, pr)
        Lita.logger.info(pr_h.inspect)
      end

      def pr_comments(response)
        return false unless permit_user?(__method__, response)
        org, repo, pr = pr_match(response.match_data)
        full_name = rpo(org, repo)

        issue_h = octo.issue_comments(full_name, pr)
        Lita.logger.info(issue_h.inspect)
      end

      def pr_already_merged?(pr_h)
        pr_h[:pr][:merged]
      end

      def jenkins_checks_pass!
        self.class.pr_state[:jobs] = {}
        self.class.pr_state[:lst_jobs] = {}
        self.class.pr_state[:jenkins] = true
        self.class.pr_state[:jenkins_lst] = true
        config.jenkins_ci_jobs.each do |job|
          self.class.pr_state[:jobs][job] = jenkins_check_job_result(job)
          unless self.class.pr_state[:jobs][job] == 'passing'
            self.class.pr_state[:jenkins] = false
          end
        end
        config.jenkins_lst_jobs.each do |job|
          self.class.pr_state[:lst_jobs][job] = jenkins_check_job_result(job)
          unless self.class.pr_state[:lst_jobs][job] == 'passing' || self.class.pr_state[:lst_jobs][job] == 'running'
            self.class.pr_state[:jenkins_lst] = false
          end
        end
      end

      def jenkins_check_job_result(query_job)
        jenkins_jobs.each do |job|
          if job['name'] == query_job
            return jenkins_map_result(job['color'])
          else
            next
          end
        end
        'notfound'
      end

      def jenkins_map_result(color)
        case color
        when 'blue'
          return 'passing'
        when 'red','red_anime','aborted'
          return 'fail'
        else
          return 'running'
        end
      end

      def jenkins_jobs
        path = "#{config.jenkins_url}/api/json"
        response = http.get(path)
        JSON.parse(response.body)["jobs"]
      end

      def pr_test_pass!(response, pr_h)
        org, repo, pr = pr_match(response.match_data)
        full_name = rpo(org, repo)

        build_status = octo.combined_status(full_name, pr_h[:pr][:head][:sha])[:state]
        self.class.pr_state[:build_status] = build_status
        if build_status == "success"
          self.class.pr_state[:test] = true
        else
          self.class.pr_state[:test] = false
        end
      end

      def pr_review_pass!(response, pr_h)
        self.class.pr_state[:reviewer] = "None"
        self.class.pr_state[:review] = false
        org, repo, pr = pr_match(response.match_data)
        full_name = rpo(org, repo)
        # Get the original user
        user = pr_h[:pr][:user][:login]

        # Get all comments
        issue_comments_h = octo.issue_comments(full_name, pr)
        issue_comments_h.each do |comment|
          if comment[:user][:login] != user
            if comment[:body].match(/:\+1:/)
              self.class.pr_state[:reviewer] = comment[:user][:login]
              self.class.pr_state[:comment] = comment[:body]
              self.class.pr_state[:review] = true
              return
            end
          end
        end
      end

      def pr_merge(response)
        # Is this function disabled?
        return response.reply(t('method_disabled')) if func_disabled?(__method__)

        # Lockdown restricts merging to a limited group of folks - if lockdown
        # is not enabled, anyone may trigger a merge - all pre-merge validation
        # checks apply either way
        unless lockdown_status(response)[:state] == "disabled"
          return false unless permit_user?(__method__, response)
          response.reply("Lockdown presently enabled")
        end

        org, repo, pr = pr_match(response.match_data)
        fullname = rpo(org, repo)

        pr_h = pull_request(fullname, pr)

        return response.reply(t('not_found', pr: pr, org: org, repo: repo)) if pr_h[:fail] && pr_h[:not_found]

        # Check to make sure the PR isn't already merged
        if pr_already_merged?(pr_h)
          response.reply("PR #{pr} is already merged yo!")
          return false
        end

        # Perform all pre-merge validation checks
        unless pr_pre_merge_pass?(response, pr_h)
          response.reply("Pre-merge checks failed - will not merge PR")
          pr_show_state(response)
          return false
        end


        # Add comment about who requested merge
        comment = "Merge triggered by #{response.user.name}"
        octo.add_comment(fullname, pr, comment)

        branch = pr_h[:pr][:head][:ref]
        title = pr_h[:pr][:title]
        commit = "Merge pull request ##{pr} from #{org}/#{branch}\n\n#{title}"

        status = merge_pr(org, repo, pr, commit)

        if !defined?(status) || status.nil?
          response.reply(t('exception'))
        elsif status[:merged]
          response.reply(t('pr_merge.pass', pr: pr, org: org, branch: branch, title: title))
        else
          url = "https://github.com/#{org}/#{repo}/pull/#{pr}"
          response.reply(t('pr_merge.fail', pr: pr, title: title, url: url, msg: status[:message]))
        end
      end
      # rubocop:enable Metrics/CyclomaticComplexity
      # rubocop:enable Metrics/PerceivedComplexity

      def pr_list(response)
        org, repo = repo_match(response.match_data)
        full_name = rpo(org, repo)
        reply = ''

        prs = octo.pull_requests(full_name)

        if prs.length > LitaGithub::Repo::PR_LIST_MAX_COUNT
          reply = t('pr_list.large_list', max: LitaGithub::Repo::PR_LIST_MAX_COUNT)

          prs.slice(0, 10).each { |pr| reply << list_line(pr, full_name) }

          reply << "----\n"

          prs.slice(-10, 10).each { |pr| reply << list_line(pr, full_name) }
        elsif prs.length > 0
          prs.each { |pr| reply << list_line(pr, full_name) }
        else
          reply = t('pr_list.no_prs')
        end

        response.reply(reply)
      end

      private

      def pr_match(md)
        [organization(md['org']), md['repo'], md['pr']]
      end

      def pr_label_match(md)
        [organization(md['org']), md['repo'], md['pr'], md['label']]
      end

      def pr_assign_match(md)
        [organization(md['org']), md['repo'], md['pr'], md['user']]
      end

      def pull_request(full_name, pr_num)
        ret = { fail: false, not_found: false }
        begin
          ret[:pr] = octo.pull_request(full_name, pr_num)
        rescue Octokit::NotFound
          ret[:fail] = true
          ret[:not_found] = true
        end
        ret
      end

      def build_pr_info(pr_obj, full_name)
        info = {}

        build_pr_header!(info, pr_obj)
        build_pr_commitinfo!(info, pr_obj)
        build_pr_status!(info, pr_obj, full_name)
        build_pr_merge!(info, pr_obj)
        build_pr_comments!(info, pr_obj)

        info
      end

      def merge_pr(org, repo, pr, commit)
        status = nil
        # rubocop:disable Lint/HandleExceptions
        begin
          status = octo.merge_pull_request(rpo(org, repo), pr, commit)
        rescue StandardError
          # no-op
        end
        # rubocop:enable Lint/HandleExceptions
        status
      end

      def build_pr_label!(info, pr_obj)
        info[:title]            = pr_obj[:title]
        info[:number]           = pr_obj[:number]
        info[:url]              = pr_obj[:html_url]
        info
      end

      def build_pr_header!(info, pr_obj)
        info[:title]            = pr_obj[:title]
        info[:number]           = pr_obj[:number]
        info[:url]              = pr_obj[:html_url]
        info
      end

      def build_pr_commitinfo!(info, pr_obj)
        info[:commits]          = pr_obj[:commits]
        info[:plus]             = pr_obj[:additions]
        info[:minus]            = pr_obj[:deletions]
        info[:changed_files]    = pr_obj[:changed_files]
        info[:pr_sha]           = pr_obj[:head][:sha]
        info[:base_sha]         = pr_obj[:base][:sha]
        info[:pr_sha_short]     = info[:pr_sha].slice(0, 7)
        info
      end

      def build_pr_status!(info, pr_obj, full_name)
        user = octo.user(pr_obj[:user][:login])
        if not pr_obj[:assignee].nil?
          assignee = pr_obj[:assignee][:login]
        else
          assignee = "None"
        end
        info[:user]             = pr_obj[:user][:login]
        info[:user]             << " (#{user[:name]})" if user.key?(:name)
        info[:assignee]         = assignee
        info[:state]            = pr_obj[:merged] ? :merged : pr_obj[:state].to_sym
        info[:state_str]        = pr_obj[:merged] ? 'Merged' : pr_obj[:state].capitalize
        info[:build_status]     = octo.combined_status(full_name, info[:pr_sha])[:state]
        info
      end

      def build_pr_merge!(info, pr_obj)
        info[:mergeable]        = pr_obj[:mergeable]
        if info[:state] == :merged
          merger = octo.user(pr_obj[:merged_by][:login])
          info[:merged_by] = pr_obj[:merged_by][:login]
          info[:merged_by] << " (#{merger[:name]})" if merger.key?(:name)
        end
        info
      end

      def build_pr_comments!(info, pr_obj)
        info[:review_comments]  = pr_obj[:review_comments]
        info[:comments]         = pr_obj[:comments]
        info
      end

      def list_line(pr, full_name)
        t('pr_info.header_long', build_pr_header!({}, pr).merge(repo: full_name, u: pr[:user][:login]))
      end
    end

    Lita.register_handler(GithubPR)
  end
end
