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

require 'spec_helper'

describe Lita::Handlers::GithubPR, lita_handler: true do
  # pr_merge command routing
  it { is_expected.to route_command('gh shipit GrapeDuty/lita-test #42').to(:pr_merge) }
  it { is_expected.to route_command('gh shipit lita-test #42').to(:pr_merge) }
  it { is_expected.to route_command('gh pr merge lita-test #42').to(:pr_merge) }
  it { is_expected.to route_command('gh pr merge GrapeDuty/lita-test #42').to(:pr_merge) }
  it { is_expected.to route_command('shipit GrapeDuty/lita-test #42').to(:pr_merge) }
  it { is_expected.to route_command('shipit lita-test #42').to(:pr_merge) }

  # pr_info command routing
  it { is_expected.to route_command('gh pr info GrapeDuty/lita-test #42').to(:pr_info) }
  it { is_expected.to route_command('gh pr info lita-test #42').to(:pr_info) }

  # pr_label command routing
  it { is_expected.to route_command('gh pr label lita-test #42 somelabel').to(:pr_add_label) }
  it { is_expected.to route_command('gh pr rmlabel lita-test #42 somelabel').to(:pr_rm_label) }

  # pr_list command routing
  it { is_expected.to route_command('gh pr list GrapeDuty/lita-test').to(:pr_list) }
  it { is_expected.to route_command('gh pr list lita-test').to(:pr_list) }

  let(:github_pr) { Lita::Handlers::GithubPR.new('robot') }
  let(:github_org) { 'GrapeDuty' }
  let(:github_repo) { 'lita-test' }
  let(:full_name) { "#{github_org}/#{github_repo}" }
  let(:disabled_reply) { 'Sorry, this function has either been disabled or not enabled in the config' }

  ####
  # Helper Methods
  ####
  describe '.pr_match' do
    it 'should return the content of the match data' do
      mock_md = { 'org' => github_org, 'repo' => github_repo, 'pr' => 42 }
      expect(github_pr.send(:pr_match, mock_md)).to eql [github_org, github_repo, 42]
    end
  end

  describe '.merge_pr' do
    before do
      @octo_obj = double('Octokit::Client', merge_pull_request: :ohai)
      allow(github_pr).to receive(:octo).and_return(@octo_obj)
    end

    let(:pr_num) { 42 }
    let(:ref) { '1234567890' }

    context 'when all goes to plan' do
      it 'should call octo.merge_pull_request with the proper args' do
        expect(@octo_obj).to receive(:merge_pull_request).with(full_name, pr_num, ref)
          .and_return(:ohai)
        github_pr.send(:merge_pr, github_org, github_repo, pr_num, ref)
      end

      it 'should return the return of octo.merge_pull_request' do
        x = github_pr.send(:merge_pr, github_org, github_repo, 42, '1234567890')
        expect(x).to eql :ohai
      end
    end

    context 'when the merging throws an exception' do
      before do
        allow(@octo_obj).to receive(:merge_pull_request).with(full_name, pr_num, ref)
          .and_raise(StandardError.new)
      end

      it 'should return nil' do
        expect(github_pr.send(:merge_pr, github_org, github_repo, pr_num, ref)).to be_nil
      end
    end
  end

  describe '.build_pr_header!' do
    let(:pr_obj) do
      { title: 'abc123', number: 42, html_url: 'https://github.com/' }
    end

    it 'should return a Hash' do
      info = {}
      x = github_pr.send(:build_pr_header!, info, pr_obj)
      expect(x).to be_an_instance_of Hash
    end

    it 'should set the :title key' do
      info = {}
      github_pr.send(:build_pr_header!, info, pr_obj)
      expect(info[:title]).to eql pr_obj[:title]
    end

    it 'should set the :number key' do
      info = {}
      github_pr.send(:build_pr_header!, info, pr_obj)
      expect(info[:number]).to eql pr_obj[:number]
    end

    it 'should set the :url key' do
      info = {}
      github_pr.send(:build_pr_header!, info, pr_obj)
      expect(info[:url]).to eql pr_obj[:html_url]
    end
  end

  describe '.build_pr_commitinfo!' do
    let(:pr_obj) do
      {
        commits: 1, additions: 4, deletions: 2, changed_files: 1,
        head: { sha: '1234567890' }, base: { sha: '0987654321' }
      }
    end
    let(:info) { {} }

    it 'should return a Hash' do
      expect(github_pr.send(:build_pr_commitinfo!, info, pr_obj)).to be_an_instance_of Hash
    end

    it 'should set the :commits key' do
      github_pr.send(:build_pr_commitinfo!, info, pr_obj)
      expect(info[:commits]).to eql pr_obj[:commits]
    end

    it 'should set the :plus key' do
      github_pr.send(:build_pr_commitinfo!, info, pr_obj)
      expect(info[:plus]).to eql pr_obj[:additions]
    end

    it 'should set the :minus key' do
      github_pr.send(:build_pr_commitinfo!, info, pr_obj)
      expect(info[:minus]).to eql pr_obj[:deletions]
    end

    it 'should set the :changed_files key' do
      github_pr.send(:build_pr_commitinfo!, info, pr_obj)
      expect(info[:changed_files]).to eql pr_obj[:changed_files]
    end

    it 'should set the :pr_sha key' do
      github_pr.send(:build_pr_commitinfo!, info, pr_obj)
      expect(info[:pr_sha]).to eql pr_obj[:head][:sha]
    end

    it 'should be set the :base_sha key' do
      github_pr.send(:build_pr_commitinfo!, info, pr_obj)
      expect(info[:base_sha]).to eql pr_obj[:base][:sha]
    end

    it 'should set the :pr_sha_short key' do
      github_pr.send(:build_pr_commitinfo!, info, pr_obj)
      expect(info[:pr_sha_short]).to eql info[:pr_sha].slice(0, 7)
    end
  end

  describe '.build_pr_status!' do
    before do
      @user_obj = { name: 'Tim Heckman' }
      @cs_obj = { state: 'success' }
      @octo_obj = double('Octokit::Client', user: @user_obj, combined_status: @cs_obj)
      allow(github_pr).to receive(:octo).and_return(@octo_obj)
    end

    let(:pr_obj) do
      {
        user: { login: 'theckman' }, state: 'closed', merged: true, pr_sha: '1234567890'
      }
    end
    let(:info) { { pr_sha: '1234567890' } }

    it 'should return an instance of Hash' do
      expect(github_pr.send(:build_pr_status!, info, pr_obj, full_name))
        .to be_an_instance_of Hash
    end

    it 'should call octo.user' do
      expect(@octo_obj).to receive(:user).with('theckman')
      github_pr.send(:build_pr_status!, info, pr_obj, full_name)
    end

    it 'should call octo.combined_status and set it to :build_status' do
      expect(@octo_obj).to receive(:combined_status)
        .with(full_name, '1234567890')
        .and_return(@cs_obj)
      github_pr.send(:build_pr_status!, info, pr_obj, full_name)
      expect(info[:build_status]).to eql 'success'
    end

    context 'when user has a name set' do
      it 'should include the name' do
        github_pr.send(:build_pr_status!, info, pr_obj, full_name)
        expect(info[:user]).to eql 'theckman (Tim Heckman)'
      end
    end

    context 'when the PR has been merged' do
      it 'should set the :state key to :merged' do
        github_pr.send(:build_pr_status!, info, pr_obj, full_name)
        expect(info[:state]).to eql :merged
      end

      it 'should set the :state_str to "Merged"' do
        github_pr.send(:build_pr_status!, info, pr_obj, full_name)
        expect(info[:state_str]).to eql 'Merged'
      end
    end

    context 'when user has no name set' do
      before do
        @octo_obj = double('Octokit::Client', user: {}, combined_status: @cs_obj)
        allow(github_pr).to receive(:octo).and_return(@octo_obj)
      end

      it 'should not include the real name parenthesis' do
        github_pr.send(:build_pr_status!, info, pr_obj, full_name)
        expect(info[:user]).to eql 'theckman'
      end
    end

    context 'when PR not merged' do
      context 'when status is open' do
        let(:pr_obj) do
          {
            user: { login: 'theckman' }, state: 'open', merged: false
          }
        end

        it 'should set the :state key to :open' do
          github_pr.send(:build_pr_status!, info, pr_obj, full_name)
          expect(info[:state]).to eql :open
        end

        it 'should set the :state_str to "Open"' do
          github_pr.send(:build_pr_status!, info, pr_obj, full_name)
          expect(info[:state_str]).to eql 'Open'
        end
      end

      context 'when status is closed' do
        let(:pr_obj) do
          {
            user: { login: 'theckman' }, state: 'closed', merged: false
          }
        end

        it 'should set the :state key to :closed' do
          github_pr.send(:build_pr_status!, info, pr_obj, full_name)
          expect(info[:state]).to eql :closed
        end

        it 'should set the :state_str to "Closed"' do
          github_pr.send(:build_pr_status!, info, pr_obj, full_name)
          expect(info[:state_str]).to eql 'Closed'
        end
      end
    end
  end

  describe '.build_pr_merge!' do
    before do
      @user_obj = { name: 'Tim Heckman' }
      @octo_obj = double('Octokit::Client', user: @user_obj)
      allow(github_pr).to receive(:octo).and_return(@octo_obj)
    end

    let(:pr_obj) do
      {
        state: :open, mergeable: true
      }
    end
    let(:info) { { state: :open } }

    it 'should return an instance of Hash' do
      expect(github_pr.send(:build_pr_merge!, info, pr_obj))
        .to be_an_instance_of Hash
    end

    it 'should set the :mergable key' do
      github_pr.send(:build_pr_merge!, info, pr_obj)
      expect(info[:mergeable]).to eql true
    end

    context 'when not merged' do
      it 'should not set the :merged_by key' do
        github_pr.send(:build_pr_merge!, info, pr_obj)
        expect(info.key?(:merged_by)).to be_falsey
      end
    end

    context 'when merged' do
      let(:pr_obj) do
        {
          state: :merged, mergeable: nil, merged_by: { login: 'theckman' }
        }
      end
      let(:info) { { state: :merged } }

      it 'should grab some user info about who merged' do
        expect(@octo_obj).to receive(:user).with('theckman').and_return(@user_obj)
        github_pr.send(:build_pr_merge!, info, pr_obj)
      end

      context 'when user has a name field' do
        it 'should set the :merged_by key' do
          github_pr.send(:build_pr_merge!, info, pr_obj)
          expect(info[:merged_by]).to eql 'theckman (Tim Heckman)'
        end
      end

      context 'when the user has no name field' do
        before do
          @user_obj = {}
          @octo_obj = double('Octokit::Client', user: @user_obj)
          allow(github_pr).to receive(:octo).and_return(@octo_obj)
        end

        it 'should set the :merged_by key without parenthesis' do
          github_pr.send(:build_pr_merge!, info, pr_obj)
          expect(info[:merged_by]).to eql 'theckman'
        end
      end
    end
  end

  describe '.build_pr_comments!' do
    let(:pr_obj) { { comments: 1, review_comments: 3 } }
    let(:info) { {} }

    it 'should return a Hash' do
      expect(github_pr.send(:build_pr_comments!, info, pr_obj)).to be_an_instance_of Hash
    end

    it 'should set the :comments key' do
      github_pr.send(:build_pr_comments!, info, pr_obj)
      expect(info[:comments]).to eql 1
    end

    it 'should set the :review_comments key' do
      github_pr.send(:build_pr_comments!, info, pr_obj)
      expect(info[:review_comments]).to eql 3
    end
  end

  describe '.build_pr_info' do
    before do
      allow(github_pr).to receive(:build_pr_header!).and_return(nil)
      allow(github_pr).to receive(:build_pr_commitinfo!).and_return(nil)
      allow(github_pr).to receive(:build_pr_status!).and_return(nil)
      allow(github_pr).to receive(:build_pr_merge!).and_return(nil)
      allow(github_pr).to receive(:build_pr_comments!).and_return(nil)
    end

    let(:pr_obj) { :ohai }

    it 'should return an instance of Hash' do
      expect(github_pr.send(:build_pr_info, pr_obj, full_name)).to be_an_instance_of Hash
    end

    it 'should call .build_pr_header!' do
      expect(github_pr).to receive(:build_pr_header!).with({}, pr_obj).and_return(nil)
      github_pr.send(:build_pr_info, pr_obj, full_name)
    end

    it 'should call .build_pr_commitinfo!' do
      expect(github_pr).to receive(:build_pr_commitinfo!).with({}, pr_obj).and_return(nil)
      github_pr.send(:build_pr_info, pr_obj, full_name)
    end

    it 'should call .build_pr_status!' do
      expect(github_pr).to receive(:build_pr_status!).with({}, pr_obj, full_name).and_return(nil)
      github_pr.send(:build_pr_info, pr_obj, full_name)
    end

    it 'should call .build_pr_merge!' do
      expect(github_pr).to receive(:build_pr_merge!).with({}, pr_obj).and_return(nil)
      github_pr.send(:build_pr_info, pr_obj, full_name)
    end

    it 'should call .build_pr_comments!' do
      expect(github_pr).to receive(:build_pr_comments!).with({}, pr_obj).and_return(nil)
      github_pr.send(:build_pr_info, pr_obj, full_name)
    end
  end

  describe '.list_line' do
    let(:pr) { { title: 'Test', number: 42, html_url: 'nothtml', user: { login: 'theckman' } } }
    let(:full_name) { 'GrapeDuty/lita-test' }

    it 'should return a PR header' do
      l = github_pr.send(:list_line, pr, full_name)
      expect(l).to eql "GrapeDuty/lita-test #42: 'Test' opened by theckman :: nothtml\n"
    end
  end

  ####
  # Handlers
  ####
  describe '.merge_pr' do
    before do
      @merge_status = { sha: 'abc456', merged: true, message: 'Pull Request successfully merged' }
      @octo_obj = double('Octokit::Client', merge_pull_request: @merge_status)
      allow(github_pr).to receive(:octo).and_return(@octo_obj)
    end

    context 'when all goes well' do
      it 'should return the response from trying to merge' do
        expect(github_pr.send(:merge_pr, github_org, github_repo, '42', 'test commit'))
          .to eql @merge_status
      end
    end

    context 'when we hit an exception' do
      before do
        @merge_status = { sha: 'abc456', merged: false, message: '*BOOM*' }
        @octo_obj = double('Octokit::Client')
        allow(@octo_obj).to receive(:merge_pull_request).and_raise(StandardError.new)
        allow(github_pr).to receive(:octo).and_return(@octo_obj)
      end

      it 'should return nil' do
        expect(github_pr.send(:merge_pr, github_org, github_repo, 42, 'test commit'))
          .to be_nil
      end
    end
  end

  describe '.pr_info' do
    context 'when PR is not merged' do
      before do
        @pr_info = {
          title: 'Test Pull Request (Not Real)', number: 42,
          url: "https://github.com/#{github_org}/#{github_repo}/pulls/42",
          commits: 1, plus: 42, minus: 0, changed_files: 1, pr_sha: '1234567890',
          base_sha: '0987654321', pr_sha_short: '1234567', user: 'theckman (Tim Heckman)',
          state: :open, state_str: 'Open', build_status: 'success', mergeable: true,
          review_comments: 2, comments: 1
        }
        @pr_resp = { fail: false, not_found: false, pr: @pr_info }
        allow(github_pr).to receive(:pull_request).and_return(@pr_resp)
        allow(github_pr).to receive(:build_pr_info).and_return(@pr_info)
      end

      it 'should reply with the expeced output' do
        r = "GrapeDuty/lita-test #42: 'Test Pull Request (Not Real)' :: " \
              "https://github.com/GrapeDuty/lita-test/pulls/42\n" \
              "Opened By: theckman (Tim Heckman) | State: Open | Build: success | Mergeable: true\n" \
              'Head: 1234567 | Commits: 1 (+42/-0) :: ' \
              "https://github.com/GrapeDuty/lita-test/compare/0987654321...1234567890\n" \
              "PR Comments: 1 | Code Comments: 2\n"
        send_command("gh pr info #{github_org}/#{github_repo} #42")
        expect(replies.last).to eql r
      end
    end

    context 'when the PR has been merged' do
      before do
        @pr_info = {
          title: 'Test Pull Request (Not Real)', number: 42,
          url: "https://github.com/#{github_org}/#{github_repo}/pulls/42",
          commits: 1, plus: 42, minus: 0, changed_files: 1, pr_sha: '1234567890',
          base_sha: '0987654321', pr_sha_short: '1234567', user: 'theckman (Tim Heckman)',
          state: :merged, state_str: 'Merged', build_status: 'success', mergeable: true,
          merged_by: 'theckman (Tim Heckman)', review_comments: 2, comments: 1
        }
        @pr_resp = { fail: false, not_found: false, pr: @pr_info }
        allow(github_pr).to receive(:pull_request).and_return(@pr_resp)
        allow(github_pr).to receive(:build_pr_info).and_return(@pr_info)
      end

      it 'should reply with the expeced output' do
        r = "GrapeDuty/lita-test #42: 'Test Pull Request (Not Real)' :: " \
              "https://github.com/GrapeDuty/lita-test/pulls/42\n" \
              'Opened By: theckman (Tim Heckman) | State: Merged | Build: success | ' \
              "Merged By: theckman (Tim Heckman)\n" \
              'Head: 1234567 | Commits: 1 (+42/-0) :: ' \
              "https://github.com/GrapeDuty/lita-test/compare/0987654321...1234567890\n" \
              "PR Comments: 1 | Code Comments: 2\n"
        send_command("gh pr info #{github_org}/#{github_repo} #42")
        expect(replies.last).to eql r
      end
    end

    context 'when the PR was not found' do
      before do
        @pr_resp = { fail: true, not_found: true, pr: @pr_info }
        allow(github_pr).to receive(:pull_request).and_return(@pr_resp)
      end

      it 'should reply with the not found error' do
        send_command("gh pr info #{github_org}/#{github_repo} #42")
        expect(replies.last).to eql 'Pull request #42 on GrapeDuty/lita-test not found'
      end
    end
  end

  describe '.pr_merge' do
    before do
      @cfg_obj = double('Lita::Configuration', pr_merge_enabled: true)
      @pr_obj =  { head: { ref: 'fix-some-bugs' }, title: 'fix bug' }
      @merge_status = { sha: 'abc456', merged: true, message: 'Pull Request successfully merged' }
      @octo_obj = double('Octokit::Client', pull_request: @pr_obj)
      allow(github_pr).to receive(:octo).and_return(@octo_obj)
      allow(github_pr).to receive(:func_disabled?).and_return(false)
      allow(github_pr).to receive(:config).and_return(@cfg_obj)
      allow(github_pr).to receive(:merge_pr).and_return(@merge_status)
    end

    context 'when command disabled' do
      before do
        allow(github_pr).to receive(:func_disabled?).and_return(true)
      end

      it 'should no-op and say such' do
        send_command("shipit #{github_org}/#{github_repo} #42")
        expect(replies.last).to eql disabled_reply
      end
    end

    context 'when repo not found' do
      before do
        allow(@octo_obj).to receive(:pull_request).and_raise(Octokit::NotFound.new)
      end

      it 'should reply indicating it was invalid' do
        send_command("shipit #{github_org}/#{github_repo} #42")
        expect(replies.last).to eql 'Pull request #42 on GrapeDuty/lita-test not found'
      end
    end

    context 'when merging should succeed' do
      it 'should set the right commit message' do
        expect(github_pr).to receive(:merge_pr).with(
          'GrapeDuty', 'lita-test', '42', "Merge pull request #42 from GrapeDuty/fix-some-bugs\n\nfix bug"
        )
        send_command('shipit GrapeDuty/lita-test #42')
      end

      it 'should confirm merging of PR' do
        send_command("shipit #{github_org}/#{github_repo} #42")
        expect(replies.last)
          .to eql "Merged pull request #42 from GrapeDuty/fix-some-bugs\nfix bug"
      end
    end

    context 'when merging bombs' do
      before do
        @merge_status = { sha: 'abc456', merged: false, message: '*BOOM*' }
        allow(github_pr).to receive(:merge_pr).and_return(@merge_status)
      end

      it 'should confirm the failure' do
        send_command("shipit #{github_org}/#{github_repo} #42")
        expect(replies.last)
          .to eql(
            "Failed trying to merge PR #42 (fix bug) :: https://github.com/GrapeDuty/lita-test/pull/42\n"\
              'Message: *BOOM*'
          )
      end
    end

    context 'when the API request explodes' do
      before do
        @merge_status = { sha: 'abc456', merged: false, message: '*BOOM*' }
        @octo_obj = double('Octokit::Client', pull_request: @pr_obj)
        allow(github_pr).to receive(:merge_pr).and_return(nil)
      end

      it 'should confirm the failure' do
        send_command("shipit #{github_org}/#{github_repo} #42")
        expect(replies.last)
          .to eql(
            'An unexpected exception was hit during the GitHub API operation. Please make sure all ' \
              'arguments are proper and try again, or try checking the GitHub status (gh status)'
          )
      end
    end
  end

  describe '.pr_list' do
    before do
      cfg_obj = double('Lita::Configuration')
      octo_obj = double('Octokit::Client', pull_requests: [])
      allow(github_pr).to receive(:octo).and_return(octo_obj)
      allow(github_pr).to receive(:config).and_return(cfg_obj)
    end

    context 'when there are no pull requests' do
      it 'should state that there are no pull requests' do
        send_command("gh pr list #{github_org}/#{github_repo}")
        expect(replies.last).to eql 'This repo has no open pull requests; good job!'
      end
    end

    context 'when there are less than 20 prs' do
      before do
        pr = [
          { title: 'Test2', number: 84, html_url: 'nohtmlurl', user: { login: 'theckman' } },
          { title: 'Test1', number: 42, html_url: 'htmlurl', user: { login: 'theckman' } }
        ]
        octo_obj = double('Octokit::Client', pull_requests: pr)
        allow(github_pr).to receive(:octo).and_return(octo_obj)
      end

      it 'should reply with the PRs' do
        send_command("gh pr list #{github_org}/#{github_repo}")
        expect(replies.last).to eql "GrapeDuty/lita-test #84: 'Test2' opened by theckman :: nohtmlurl\n" \
                                    "GrapeDuty/lita-test #42: 'Test1' opened by theckman :: htmlurl\n"
      end
    end

    context 'when there are more than 20 prs' do
      before do
        pr = [
          { title: 'Test21', number: 84, html_url: 'xxx', user: { login: 'theckman' } },
          { title: 'Test20', number: 83, html_url: 'xxx', user: { login: 'theckman' } },
          { title: 'Test19', number: 82, html_url: 'xxx', user: { login: 'theckman' } },
          { title: 'Test18', number: 80, html_url: 'xxx', user: { login: 'theckman' } },
          { title: 'Test17', number: 78, html_url: 'xxx', user: { login: 'theckman' } },
          { title: 'Test16', number: 74, html_url: 'xxx', user: { login: 'theckman' } },
          { title: 'Test15', number: 68, html_url: 'xxx', user: { login: 'theckman' } },
          { title: 'Test14', number: 66, html_url: 'xxx', user: { login: 'theckman' } },
          { title: 'Test13', number: 64, html_url: 'xxx', user: { login: 'theckman' } },
          { title: 'Test12', number: 55, html_url: 'xxx', user: { login: 'theckman' } },
          { title: 'Test11', number: 52, html_url: 'xxx', user: { login: 'theckman' } },
          { title: 'Test10', number: 51, html_url: 'xxx', user: { login: 'theckman' } },
          { title: 'Test9', number: 50, html_url: 'xxx', user: { login: 'theckman' } },
          { title: 'Test8', number: 49, html_url: 'xxx', user: { login: 'theckman' } },
          { title: 'Test7', number: 48, html_url: 'xxx', user: { login: 'theckman' } },
          { title: 'Test6', number: 47, html_url: 'xxx', user: { login: 'theckman' } },
          { title: 'Test5', number: 46, html_url: 'xxx', user: { login: 'theckman' } },
          { title: 'Test4', number: 45, html_url: 'xxx', user: { login: 'theckman' } },
          { title: 'Test3', number: 44, html_url: 'xxx', user: { login: 'theckman' } },
          { title: 'Test2', number: 43, html_url: 'xxx', user: { login: 'theckman' } },
          { title: 'Test1', number: 42, html_url: 'xxx', user: { login: 'theckman' } }
        ]
        octo_obj = double('Octokit::Client', pull_requests: pr)
        allow(github_pr).to receive(:octo).and_return(octo_obj)
      end

      it 'should return the list of ten oldest & ten newest' do
        send_command("gh pr list #{github_org}/#{github_repo}")
        expect(replies.last)
          .to eql "You have more than 20 open pull requests :(! Here are the ten newest oldest:
GrapeDuty/lita-test #84: 'Test21' opened by theckman :: xxx
GrapeDuty/lita-test #83: 'Test20' opened by theckman :: xxx
GrapeDuty/lita-test #82: 'Test19' opened by theckman :: xxx
GrapeDuty/lita-test #80: 'Test18' opened by theckman :: xxx
GrapeDuty/lita-test #78: 'Test17' opened by theckman :: xxx
GrapeDuty/lita-test #74: 'Test16' opened by theckman :: xxx
GrapeDuty/lita-test #68: 'Test15' opened by theckman :: xxx
GrapeDuty/lita-test #66: 'Test14' opened by theckman :: xxx
GrapeDuty/lita-test #64: 'Test13' opened by theckman :: xxx
GrapeDuty/lita-test #55: 'Test12' opened by theckman :: xxx
----
GrapeDuty/lita-test #51: 'Test10' opened by theckman :: xxx
GrapeDuty/lita-test #50: 'Test9' opened by theckman :: xxx
GrapeDuty/lita-test #49: 'Test8' opened by theckman :: xxx
GrapeDuty/lita-test #48: 'Test7' opened by theckman :: xxx
GrapeDuty/lita-test #47: 'Test6' opened by theckman :: xxx
GrapeDuty/lita-test #46: 'Test5' opened by theckman :: xxx
GrapeDuty/lita-test #45: 'Test4' opened by theckman :: xxx
GrapeDuty/lita-test #44: 'Test3' opened by theckman :: xxx
GrapeDuty/lita-test #43: 'Test2' opened by theckman :: xxx
GrapeDuty/lita-test #42: 'Test1' opened by theckman :: xxx
"
      end
    end
  end
end
