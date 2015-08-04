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

      on :loaded, :setup_octo # from LitaGithub::Octo

      route(
        /#{LitaGithub::R::A_REG}pr\s+?info\s+?#{LitaGithub::R::REPO_REGEX}\s+?#(?<pr>\d+?)$/,
        :pr_info,
        command: true,
        help: { 'gh pr info PagerDuty/lita-github #42' => 'show some information about the pull request' }
      )

      route(
        /(?:#{LitaGithub::R::A_REG}(?:pr merge|shipit)|shipit)\s+?#{LitaGithub::R::REPO_REGEX}\s+?#(?<pr>\d+?)$/,
        :pr_merge,
        restrict_to: [ :shippers ],
        command: true,
        confirmation: true,
        help: {
          'gh shipit PagerDuty/lita-github #42' => 'ship it!',
          'gh pr merge PagerDuty/lita-github #42' => 'ship it!',
          'shipit PagerDuty/lita-github #42' => 'ship it!'
        }
      )

      route(
        /#{LitaGithub::R::A_REG}pr\s+?list\s+?#{LitaGithub::R::REPO_REGEX}/, :pr_list,
        command: true,
        help: {
          'gh pr list PagerDuty/lita-github' => 'list the 10 oldest and newest PRs'
        }
      )

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

      def pr_merge(response)
        return response.reply(t('method_disabled')) if func_disabled?(__method__)
        org, repo, pr = pr_match(response.match_data)
        fullname = rpo(org, repo)

        pr_h = pull_request(fullname, pr)
        return response.reply(t('not_found', pr: pr, org: org, repo: repo)) if pr_h[:fail] && pr_h[:not_found]

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
        info[:user]             = pr_obj[:user][:login]
        info[:user]             << " (#{user[:name]})" if user.key?(:name)
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
