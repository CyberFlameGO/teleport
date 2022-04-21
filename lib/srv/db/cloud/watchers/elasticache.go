/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package watchers

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/elasticache"
	"github.com/aws/aws-sdk-go/service/elasticache/elasticacheiface"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv/db/common"
	"github.com/gravitational/trace"

	"github.com/sirupsen/logrus"
)

// elastiCacheFetcherConfig is the ElastiCache databases fetcher configuration.
type elastiCacheFetcherConfig struct {
	// Labels is a selector to match cloud databases.
	Labels types.Labels
	// ElastiCache is the ElastiCache API client.
	ElastiCache elasticacheiface.ElastiCacheAPI
	// Region is the AWS region to query databases in.
	Region string
}

// CheckAndSetDefaults validates the config and sets defaults.
func (c *elastiCacheFetcherConfig) CheckAndSetDefaults() error {
	if len(c.Labels) == 0 {
		return trace.BadParameter("missing parameter Labels")
	}
	if c.ElastiCache == nil {
		return trace.BadParameter("missing parameter ElastiCache")
	}
	if c.Region == "" {
		return trace.BadParameter("missing parameter Region")
	}
	return nil
}

// elastiCacheFetcher retrieves ElastiCache Redis databases.
type elastiCacheFetcher struct {
	cfg elastiCacheFetcherConfig
	log logrus.FieldLogger
}

// newElastiCacheFetcher returns a new ElastiCache databases fetcher instance.
func newElastiCacheFetcher(config elastiCacheFetcherConfig) (Fetcher, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return &elastiCacheFetcher{
		cfg: config,
		log: logrus.WithFields(logrus.Fields{
			trace.Component: "watch:elasticache",
			"labels":        config.Labels,
			"region":        config.Region,
		}),
	}, nil
}

// Get returns ElastiCache Redis databases matching the watcher's selectors.
//
// TODO(greedy52) support ElastiCache global datastore.
func (f *elastiCacheFetcher) Get(ctx context.Context) (types.Databases, error) {
	clusters, err := getElastiCacheClusters(ctx, f.cfg.ElastiCache)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var eligibleClusters []*elasticache.ReplicationGroup
	for _, cluster := range clusters {
		if !services.IsElastiCacheClusterSupported(cluster) {
			f.log.Debugf("ElastiCache cluster %q is not supported. Skipping.", aws.StringValue(cluster.ReplicationGroupId))
			continue
		}

		if !services.IsElastiCacheClusterAvailable(cluster) {
			f.log.Debugf("The current status of ElastiCache cluster %q is %q. Skipping.",
				aws.StringValue(cluster.ReplicationGroupId),
				aws.StringValue(cluster.Status))
			continue
		}

		eligibleClusters = append(eligibleClusters, cluster)
	}

	if len(eligibleClusters) == 0 {
		return types.Databases{}, nil
	}

	// Fetch more information to provide extra labels. Do not fail because some
	// of these labels are missing.
	//
	// Engine version is not found in elasticache.ReplicationGroup but in per
	// node details.
	//
	// Resource tags are not found in elasticache.ReplicationGroup but can be
	// on obtained by elasticache.ListTagsForResource (one call per resource).
	//
	// ElastiCache servers do not have public IPs so they are usually only
	// accessible within the same VPC. Having a VPC ID label can be useful for
	// filtering. VPC ID is obtained from subnet group details.
	nodes, err := getElastiCacheNodes(ctx, f.cfg.ElastiCache)
	if err != nil {
		if trace.IsAccessDenied(err) {
			f.log.WithError(err).Debug("No permissions to describe nodes")
		} else {
			f.log.WithError(err).Info("Failed to describe nodes.")
		}
	}
	subnetGroups, err := getElastiCacheSubnetGroups(ctx, f.cfg.ElastiCache)
	if err != nil {
		if trace.IsAccessDenied(err) {
			f.log.WithError(err).Debug("No permissions to describe subnet groups")
		} else {
			f.log.WithError(err).Info("Failed to describe subnet groups.")
		}
	}

	var databases types.Databases
	for _, cluster := range eligibleClusters {
		tags, err := getElastiCacheTagsForCluster(ctx, f.cfg.ElastiCache, cluster)
		if err != nil {
			if trace.IsAccessDenied(err) {
				f.log.WithError(err).Debug("No permissions to list resource tags")
			} else {
				f.log.WithError(err).Infof("Failed to list tags for ElastiCache cluster %q.", aws.StringValue(cluster.ReplicationGroupId))
			}
		}

		// Create database using configuration endpoint for Redis with Cluster
		// mode enabled.
		if aws.BoolValue(cluster.ClusterEnabled) {
			if database, err := services.NewDatabaseFromElastiCacheConfigurationEndpoint(cluster); err != nil {
				f.log.Infof("Could not convert ElastiCache cluster %q to database resource: %v.",
					aws.StringValue(cluster.ReplicationGroupId), err)
			} else {
				databases = append(databases, services.UpdateElastiCacheDatabaseLabels(database, tags, nodes, subnetGroups))
			}

			continue
		}

		// Create databases using primary and reader endpoints for Redis with
		// Cluster mode disabled.
		if databasesFromNodeGroups, err := services.NewDatabasesFromElastiCacheNodeGroups(cluster); err != nil {
			f.log.Infof("Could not convert ElastiCache cluster %q to database resource: %v.",
				aws.StringValue(cluster.ReplicationGroupId), err)
		} else {
			for _, database := range databasesFromNodeGroups {
				databases = append(databases, services.UpdateElastiCacheDatabaseLabels(database, tags, nodes, subnetGroups))
			}
		}
	}

	return filterDatabasesByLabels(databases, f.cfg.Labels, f.log), nil
}

// String returns the fetcher's string description.
func (f *elastiCacheFetcher) String() string {
	return fmt.Sprintf("elastiCacheFetcher(Region=%v, Labels=%v)",
		f.cfg.Region, f.cfg.Labels)
}

// getElastiCacheClusters fetches all ElastiCache replication groups.
func getElastiCacheClusters(ctx context.Context, client elasticacheiface.ElastiCacheAPI) ([]*elasticache.ReplicationGroup, error) {
	var clusters []*elasticache.ReplicationGroup
	var pageNum int

	err := client.DescribeReplicationGroupsPagesWithContext(
		ctx,
		&elasticache.DescribeReplicationGroupsInput{},
		func(page *elasticache.DescribeReplicationGroupsOutput, lastPage bool) bool {
			pageNum++
			clusters = append(clusters, page.ReplicationGroups...)
			return pageNum <= maxPages
		},
	)
	return clusters, common.ConvertError(err)
}

// getElastiCacheNodes fetches all ElastiCache nodes that associated with a
// replication group.
func getElastiCacheNodes(ctx context.Context, client elasticacheiface.ElastiCacheAPI) ([]*elasticache.CacheCluster, error) {
	var nodes []*elasticache.CacheCluster
	var pageNum int

	err := client.DescribeCacheClustersPagesWithContext(
		ctx,
		&elasticache.DescribeCacheClustersInput{},
		func(page *elasticache.DescribeCacheClustersOutput, lastPage bool) bool {
			pageNum++

			// There are three types of elasticache.CacheCluster:
			// 1) a Memcache cluster.
			// 2) a Redis node belongs to a single node deployment (no TLS support).
			// 3) a Redis node belongs to a Redis replication group.
			// Only the ones belong to replication groups are wanted.
			for _, cacheCluster := range page.CacheClusters {
				if cacheCluster.ReplicationGroupId != nil {
					nodes = append(nodes, cacheCluster)
				}
			}
			return pageNum <= maxPages
		},
	)
	return nodes, common.ConvertError(err)
}

// getElastiCacheSubnetGroups fetches all ElastiCache subnet groups.
func getElastiCacheSubnetGroups(ctx context.Context, client elasticacheiface.ElastiCacheAPI) ([]*elasticache.CacheSubnetGroup, error) {
	var subnetGroups []*elasticache.CacheSubnetGroup
	var pageNum int

	err := client.DescribeCacheSubnetGroupsPagesWithContext(
		ctx,
		&elasticache.DescribeCacheSubnetGroupsInput{},
		func(page *elasticache.DescribeCacheSubnetGroupsOutput, lastPage bool) bool {
			pageNum++
			subnetGroups = append(subnetGroups, page.CacheSubnetGroups...)
			return pageNum <= maxPages
		},
	)
	return subnetGroups, common.ConvertError(err)
}

// getElastiCacheTagsForCluster fetches resource tags for provided ElastiCache
// replication group.
func getElastiCacheTagsForCluster(ctx context.Context, client elasticacheiface.ElastiCacheAPI, cluster *elasticache.ReplicationGroup) ([]*elasticache.Tag, error) {
	input := &elasticache.ListTagsForResourceInput{
		ResourceName: cluster.ARN,
	}
	output, err := client.ListTagsForResourceWithContext(ctx, input)
	if err != nil {
		return nil, common.ConvertError(err)
	}

	return output.TagList, nil
}
