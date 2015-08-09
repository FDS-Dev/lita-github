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

module LitaGithub
  # Github handler common-use methods
  #
  # @author Tim Heckman <tim@pagerduty.com>
  module Auth

    def permit_user?(method, response)
      group = auth_group(method)
      if user_in_group?(response.user, group)
        return true
      else
        response.reply('You are not authorized to perform this action')
        return false
      end

    end

    def user_in_group?(user, group)
        auth = Lita::Robot.new.auth
        if auth.user_in_group?(user, group)
          return true
        else
          return false
        end
    end

    def auth_group(method)
      gr = {
        :repo_create => :ghadmins,
        :repo_delete => :ghadmins,
        :pr_merge => :shippers
      }
      gr[method]
    end

  end
end
